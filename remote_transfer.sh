#!/usr/bin/env bash
#=====================================================================
#  remote_transfer.sh —— 交互式 SSH 远端文件夹传输助手
#
#  功能：
#    1. 以「远端地址:远端端口」单个字段采集连接目标，按最后一个冒号切分；
#       省略端口默认 22；IP 做格式校验（IPv4/IPv6），域名不校验
#    2. 首次连接先展示主机密钥指纹并请用户确认，确认前不发送任何凭证
#    3. 优先尝试公钥 / ssh-agent 免密登录，不可用时才采集密码并验证
#    4. 校验本机源目录（存在 / 是目录 / 可读），循环直到有效
#    5. 检查远端目标目录，不存在则 mkdir -p 自动创建（含多级父目录）
#    6. rsync 传输，实时显示进度、速度与预计剩余时间
#    7. 传输前统一询问一次「是否覆盖已存在文件」，该选择作用于本次全部传输
#    8. 传输后询问是否执行 HASH 校验，逐文件比对 SHA-256 并展示双方汇总值
#    9. 依赖自检：缺 sshpass 时尝试自动安装，装不上则降级为 OpenSSH
#       自带的 SSH_ASKPASS 方案（零第三方依赖）
#
#  依赖：ssh（必需）；sshpass（可选，缺失时自动安装或零依赖降级）；
#        rsync / pv（可选，仅影响速度与剩余时间的显示效果）
#
#  用法： bash remote_transfer.sh
#
#  退出码：0 成功 / 1 失败或中断 / 2 传输成功但 HASH 不一致 /
#          3 传输成功但 HASH 校验未能完成
#=====================================================================
set -uo pipefail

#--------------------- 全局变量 ---------------------
SSH_HOST=""
SSH_USER=""
SSH_PORT=""
SSH_PASS=""
SSH_CONNECT_TIMEOUT=10      # 单次连接超时（秒）

# 认证方式：1 = 公钥 / ssh-agent 免密（不采集密码），0 = 密码
USE_KEY_AUTH=0
# 主机密钥策略：确认指纹前不连接；确认后固定为 yes（密钥变更即拒绝）
SSH_HOSTKEY_OPT=""
KNOWN_HOSTS="${HOME}/.ssh/known_hosts"
# 认证相关选项（随 USE_KEY_AUTH 变化，由 refresh_auth_opts 维护）
SSH_AUTH_OPTS=(-o PreferredAuthentications=password,keyboard-interactive
               -o PubkeyAuthentication=no -o NumberOfPasswordPrompts=1)

LOCAL_ABS=""                # 本机源目录的绝对路径
REMOTE_DIR=""                # 远端目标目录
FINAL_DIR=""                 # 远端最终生成的目录（REMOTE_DIR/basename）
REPLY_VALUE=""               # ask_required 的返回值载体

HAVE_RSYNC_LOCAL=0
HAVE_RSYNC_REMOTE=0
HAVE_PV=0
RSYNC_INFO_OPT=""

# 密码注入方式：sshpass | askpass-native | askpass-setsid
AUTH_BACKEND=""
ASKPASS_MODE=""
ASKPASS_DIR=""
ASKPASS_FILE=""
SETSID_FLAG=""

# 覆盖策略：1 = 覆盖同名文件，0 = 跳过已存在文件（一次询问，作用于全部传输）
OVERWRITE=1

# 本机可用的 SHA-256 工具，启动时探测一次（避免每文件重复 command -v）
HASHER_LOCAL=""

# tar 管道各环节退出码快照，失败时用于说明是哪一环出的问题
TAR_RC_DETAIL=""

# 全部临时产物集中在一个 700 目录里，退出时整体清理
# TMPDIR 在 Git Bash / Cygwin 下常是 C:\Users\...\Temp 这类混合路径，
# 先统一成 POSIX 形式，免得 mktemp / rm / [[ -d ]] 的行为随实现而变化
TMP_BASE="${TMPDIR:-/tmp}"
TMP_BASE="${TMP_BASE//\\//}"
[[ -d $TMP_BASE ]] || TMP_BASE=/tmp
TMP_ROOT="$(mktemp -d "$TMP_BASE/rtransfer.XXXXXX" 2>/dev/null)" || {
    printf '无法创建临时目录，脚本退出。\n' >&2
    exit 1
}
TMP_ERR="$TMP_ROOT/ssh.err"
TMP_MAN_L="$TMP_ROOT/local.sha256"
TMP_MAN_R="$TMP_ROOT/remote.sha256"
: > "$TMP_ERR" 2>/dev/null || true

#--------------------- 清理与信号 ---------------------
cleanup() {
    # 脚本内保存的密码必须一并清掉（被 source 时不会污染调用者 shell）
    SSH_PASS=""
    unset SSHPASS RTRANSFER_SSH_PASS 2>/dev/null || true
    # askpass 辅助脚本里不含密码，只做删除；失败也不影响退出
    if [[ -n "${ASKPASS_FILE:-}" && -f "$ASKPASS_FILE" ]]; then
        : > "$ASKPASS_FILE" 2>/dev/null
        rm -f -- "$ASKPASS_FILE" 2>/dev/null || true
        if [[ -n "${ASKPASS_DIR:-}" && -d "$ASKPASS_DIR" ]]; then
            rmdir -- "$ASKPASS_DIR" 2>/dev/null || true
        fi
    fi
    # 只删自己 mktemp 出来的目录，避免误删
    if [[ -n "${TMP_ROOT:-}" && -d "$TMP_ROOT" && $TMP_ROOT == */rtransfer.* ]]; then
        rm -rf -- "$TMP_ROOT" 2>/dev/null || true
    fi
    return 0
}
on_interrupt() { printf '\n'; err "已被用户中断，正在安全退出……"; exit 130; }
on_term()      { err "收到终止信号，正在安全退出……"; exit 143; }
trap cleanup EXIT
trap on_interrupt INT
trap on_term TERM

#--------------------- 输出样式 ---------------------
if [[ -t 1 ]]; then
    C_RED=$'\033[31m'; C_GRN=$'\033[32m'; C_YEL=$'\033[33m'
    C_CYN=$'\033[36m'; C_BLD=$'\033[1m';  C_RST=$'\033[0m'
else
    C_RED=""; C_GRN=""; C_YEL=""; C_CYN=""; C_BLD=""; C_RST=""
fi

info() { printf '%s[信息]%s %s\n' "$C_CYN" "$C_RST" "$*"; }
ok()   { printf '%s[成功]%s %s\n' "$C_GRN" "$C_RST" "$*"; }
warn() { printf '%s[警告]%s %s\n' "$C_YEL" "$C_RST" "$*"; }
err()  { printf '%s[错误]%s %s\n' "$C_RED" "$C_RST" "$*" >&2; }
die()  { err "$*"; exit 1; }

print_banner() {
    printf '%s' "$C_BLD"
    cat <<'EOF'
==============================================================
        远端文件夹传输助手  (SSH / rsync)
        — 按提示逐项输入，Ctrl+C 可随时安全退出 —
==============================================================
EOF
    printf '%s' "$C_RST"
}

#--------------------- 字符串工具 ---------------------
# 去掉首尾空白
trim() {
    local s=$1
    s=${s#"${s%%[![:space:]]*}"}
    s=${s%"${s##*[![:space:]]}"}
    printf '%s' "$s"
}

# 去掉用户手输的一对首尾引号（支持路径中直接粘贴带引号的内容）
strip_quotes() {
    local s=$1
    if (( ${#s} >= 2 )); then
        case $s in
            \"*\") s=${s:1:${#s}-2} ;;
            \'*\') s=${s:1:${#s}-2} ;;
        esac
    fi
    printf '%s' "$s"
}

# 汇总一组退出码：返回其中第一个非零值（全为 0 则返回 0）
# 管道里任何一环失败都算失败，避免只看最后一环造成「假成功」
worst_rc() {
    local s
    for s in "$@"; do
        [[ $s =~ ^[0-9]+$ ]] || continue
        if (( s != 0 )); then
            printf '%d' "$s"
            return 0
        fi
    done
    printf '0'
}

# 拼接远端路径，避免出现 // 或多余斜杠
join_path() {
    if [[ $1 == "/" ]]; then
        printf '/%s' "$2"
    else
        printf '%s/%s' "${1%/}" "$2"
    fi
}

# 给主机名加方括号（IPv6 用于 user@host:path 形式）
host_for_remote() {
    if [[ $SSH_HOST == *:* && $SSH_HOST != \[*\] ]]; then
        printf '[%s]' "$SSH_HOST"
    else
        printf '%s' "$SSH_HOST"
    fi
}

# 把任意字符串编码成 base64（单行），用于把路径安全地送进远端 shell
to_b64() { printf '%s' "$1" | base64 | tr -d '\n'; }

#--------------------- 读取输入 ---------------------
# 读取一个非空字符串（去空白、去引号），结果放在 REPLY_VALUE
ask_required() {
    local prompt=$1 value
    while :; do
        IFS= read -r -p "$prompt" value || { printf '\n'; err "输入已结束，退出。"; exit 1; }
        value=$(strip_quotes "$(trim "$value")")
        if [[ -z $value ]]; then
            err "输入不能为空，请重新输入。"
            continue
        fi
        REPLY_VALUE=$value
        return 0
    done
}

#--------------------- 地址解析与 IP 格式校验 ---------------------
# 合法 IPv4：四段十进制、每段 0-255、禁止前导零（010 这种会被误认为八进制）
is_valid_ipv4() {
    local ip=$1 o
    local -a parts
    [[ $ip =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] || return 1
    IFS='.' read -r -a parts <<< "$ip"
    (( ${#parts[@]} == 4 )) || return 1
    for o in "${parts[@]}"; do
        (( 10#$o <= 255 )) || return 1
        [[ ${#o} -gt 1 && $o == 0* ]] && return 1
    done
    return 0
}

# 统计 IPv6 文本里占几个 16 位分组（内嵌 IPv4 记 2 组）；失败返回 1
_ipv6_group_count() {
    local s=$1 n=0 g
    if [[ $s == *.* ]]; then
        is_valid_ipv4 "${s##*:}" || return 1
        case $s in
            *:*) s=${s%:*} ;;
            *)   s="" ;;
        esac
        n=2
        [[ -z $s ]] && { printf '%d' "$n"; return 0; }
    fi
    local IFS=':'
    for g in $s; do
        [[ $g =~ ^[0-9A-Fa-f]{1,4}$ ]] || return 1
        n=$((n + 1))
    done
    printf '%d' "$n"
}

# 合法 IPv6：支持 :: 压缩（只能出现一次）、内嵌 IPv4、zone id（%eth0）
is_valid_ipv6() {
    local ip=$1 left right ln rn
    ip=${ip%%\%*}
    [[ $ip == *:* ]] || return 1
    [[ $ip =~ ^[0-9A-Fa-f:.]+$ ]] || return 1
    case $ip in
        *::*)
            [[ ${ip#*::} == *::* ]] && return 1        # :: 出现两次即非法
            left=${ip%%::*}; right=${ip#*::}
            ln=$(_ipv6_group_count "$left") || return 1
            rn=$(_ipv6_group_count "$right") || return 1
            (( ln + rn < 8 ))
            return
            ;;
        *)
            ln=$(_ipv6_group_count "$ip") || return 1
            (( ln == 8 ))
            return
            ;;
    esac
}

# 解析「远端地址:远端端口」——成功返回 0，结果写入 HOST_PART / PORT_PART，
# 必要时用 PARSE_NOTE 说明补全行为；失败返回 1，原因写入 PARSE_ERR。
#
# 解析规则（与 scp/rsync 的 host:path 习惯一致，尽量符合直觉）：
#   1. [IPv6]:端口 / [IPv6]  → 方括号内是地址，方括号后的 :端口 可选
#   2. 裸 IPv6（冒号多于 1 个且无方括号）→ 整体视为地址，端口默认 22
#   3. 只有一个冒号 → 按该冒号切分，左边地址、右边端口
#   4. 完全没有冒号 → 整体是地址，端口默认 22
#   5. 有冒号但冒号后面为空（如 1.2.3.4:）→ 视为格式错误
HOST_PART=""; PORT_PART=""; PARSE_ERR=""; PARSE_NOTE=""

parse_endpoint() {
    local s=$1 host="" port="" rest="" ncolon

    if [[ $s == \[* ]]; then
        [[ $s == *\]* ]] || { PARSE_ERR="方括号没有闭合，IPv6 应写成 [2001:db8::1]:22"; return 1; }
        host=${s#\[}; host=${host%%\]*}
        rest=${s#*\]}
        case $rest in
            "")  port="" ;;
            :*)  port=${rest#:} ;;
            *)   PARSE_ERR="方括号后面只能跟「:端口」，您输入的是「$rest」"; return 1 ;;
        esac
    else
        ncolon=${s//[^:]/}
        if (( ${#ncolon} > 1 )); then
            host=$s; port=""                     # 裸 IPv6，不含端口
        elif (( ${#ncolon} == 1 )); then
            host=${s%%:*}; port=${s##*:}         # 按最后一个（此处唯一一个）冒号切分
        else
            host=$s; port=""
        fi
    fi

    PARSE_NOTE=""
    if [[ -z $host ]]; then
        PARSE_ERR="冒号前面缺少服务器地址（正确写法如 192.168.1.10:22）"
        return 1
    fi

    if [[ -z $port ]]; then
        if [[ $s == *: ]]; then
            PARSE_ERR="冒号后面缺少端口号。不想指定端口请直接省略冒号，例如 192.168.1.10"
            return 1
        fi
        port=22
        if [[ $host == *:* ]]; then
            PARSE_NOTE="识别为 IPv6 地址且未指定端口，按默认 22 处理。若需指定端口请写成 [地址]:端口"
        else
            PARSE_NOTE="未填写端口，按默认 22 处理。"
        fi
    fi

    if ! [[ $port =~ ^[0-9]{1,5}$ ]]; then
        PARSE_ERR="端口「$port」不是数字，端口必须是 1-65535 之间的整数"
        return 1
    fi
    if (( 10#$port < 1 || 10#$port > 65535 )); then
        PARSE_ERR="端口 $port 超出范围，必须在 1-65535 之间"
        return 1
    fi
    port=$((10#$port))          # 去掉前导零，避免 ssh -p 0022 被判为非法端口

    # 地址部分：像 IP 就严格校验，否则按域名处理（域名不做格式校验）
    if [[ $host == *:* ]]; then
        if ! is_valid_ipv6 "$host"; then
            PARSE_ERR="「$host」不是合法的 IPv6 地址（IPv6 带端口请写成 [2001:db8::1]:22）"
            return 1
        fi
    elif [[ $host =~ ^[0-9.]+$ ]]; then
        if ! is_valid_ipv4 "$host"; then
            PARSE_ERR="「$host」不是合法的 IPv4 地址（需四段 0-255，且不能有前导零）"
            return 1
        fi
    elif [[ $host == *[[:space:]]* || $host == */* || $host == *@* ]]; then
        PARSE_ERR="地址「$host」含非法字符（空格、/、@ 都不允许，请只填主机名）"
        return 1
    fi

    HOST_PART=$host
    PORT_PART=$port
    return 0
}

#--------------------- 依赖检测与自动安装 ---------------------
# 识别包管理器
detect_pm() {
    local pm
    for pm in apt-get dnf yum zypper pacman apk; do
        if command -v "$pm" >/dev/null 2>&1; then
            printf '%s' "$pm"
            return 0
        fi
    done
    return 1
}

# 以 root 身份执行：本身是 root 就直接跑，否则用 sudo
as_root() {
    if (( EUID == 0 )); then
        "$@"
    elif command -v sudo >/dev/null 2>&1; then
        sudo "$@"
    else
        return 127
    fi
}

# 能否提权（决定是否值得尝试自动安装）
can_escalate() {
    (( EUID == 0 )) || command -v sudo >/dev/null 2>&1
}

# 装包命令的展示文本（只用于提示，不参与执行）
install_cmd_text() {
    local pm=$1 pkg=$2
    case $pm in
        apt-get) printf 'apt-get update -qq && apt-get install -y %s' "$pkg" ;;
        dnf)     printf 'dnf install -y %s' "$pkg" ;;
        yum)     printf 'yum install -y %s' "$pkg" ;;
        zypper)  printf 'zypper --non-interactive install %s' "$pkg" ;;
        pacman)  printf 'pacman -S --noconfirm %s' "$pkg" ;;
        apk)     printf 'apk add --no-cache %s' "$pkg" ;;
        *)       printf '安装 %s' "$pkg" ;;
    esac
}

APT_INDEX_UPDATED=0

# 安装软件包。$1 = 包名；$2 = yes 表示调用方已取得用户同意（不再二次确认）
install_package() {
    local pkg=$1 assume=${2:-no} pm cmd ans
    pm=$(detect_pm) || { err "未识别到可用的包管理器，无法自动安装 $pkg。"; return 1; }
    cmd=$(install_cmd_text "$pm" "$pkg")

    if [[ $assume != yes ]]; then
        if (( EUID == 0 )); then
            printf '  即将以 root 身份执行：%s\n' "$cmd" >&2
        elif command -v sudo >/dev/null 2>&1; then
            printf '  即将以 sudo 执行：%s\n' "$cmd" >&2
        else
            err "缺少 root 权限且没有 sudo，无法自动安装 $pkg。"
            return 1
        fi
        # read -p 的提示走 stderr，stdout 被重定向时仍然可见
        IFS= read -r -p "  是否继续？[y=安装 / n=跳过]: " ans || ans=n
        case $ans in
            y|Y) ;;
            *) info "已跳过安装 $pkg。"; return 1 ;;
        esac
    fi

    info "正在通过 $pm 安装 $pkg ……"
    if [[ $pm == apt-get ]] && (( APT_INDEX_UPDATED == 0 )); then
        # 新容器或索引过旧时不 update 必然报 "Unable to locate package"
        info "先刷新软件包索引（apt-get update）……"
        as_root env DEBIAN_FRONTEND=noninteractive apt-get update -qq || \
            warn "apt-get update 未成功，仍尝试安装。"
        APT_INDEX_UPDATED=1
    fi

    case $pm in
        # DEBIAN_FRONTEND 必须经 env 传给 sudo 之后的那条命令，写在函数前面对 sudo 无效
        apt-get) as_root env DEBIAN_FRONTEND=noninteractive apt-get install -y "$pkg" ;;
        dnf)     as_root dnf install -y "$pkg" ;;
        yum)     as_root yum install -y "$pkg" ;;
        zypper)  as_root zypper --non-interactive install "$pkg" ;;
        pacman)  as_root pacman -S --noconfirm "$pkg" ;;
        apk)     as_root apk add --no-cache "$pkg" ;;
        *)       err "不支持的包管理器：$pm"; return 1 ;;
    esac
}

# 判断 OpenSSH 是否支持 SSH_ASKPASS_REQUIRE（8.4 及以上），支持则可完全不依赖 sshpass
ssh_supports_askpass_require() {
    local v major minor
    v=$(ssh -V 2>&1)
    v=${v#*OpenSSH_}
    major=${v%%.*}
    v=${v#*.}
    minor=${v%%[!0-9]*}
    [[ $major =~ ^[0-9]+$ && $minor =~ ^[0-9]+$ ]] || return 1
    (( major > 8 || (major == 8 && minor >= 4) ))
}

# 准备零依赖的密码注入：写一个只回显环境变量的 askpass 小脚本（脚本本身不含密码）
setup_askpass() {
    ASKPASS_DIR=$(mktemp -d "$TMP_BASE/rtransfer.askpass.XXXXXX" 2>/dev/null) || return 1
    ASKPASS_FILE="$ASKPASS_DIR/askpass.sh"
    cat > "$ASKPASS_FILE" <<'ASKPASS_EOF'
#!/bin/sh
printf '%s\n' "${RTRANSFER_SSH_PASS:?}"
ASKPASS_EOF
    chmod 700 "$ASKPASS_FILE" 2>/dev/null

    if ssh_supports_askpass_require; then
        ASKPASS_MODE="askpass-native"        # OpenSSH >= 8.4，无需 setid，原生支持
        return 0
    fi

    # 老版本 OpenSSH：需要脱离控制终端，靠 setsid 实现
    if command -v setsid >/dev/null 2>&1; then
        if setsid --wait true >/dev/null 2>&1; then
            SETSID_FLAG="--wait"
        elif setsid -w true >/dev/null 2>&1; then
            SETSID_FLAG="-w"
        else
            SETSID_FLAG=""
        fi
        if [[ -n $SETSID_FLAG ]]; then
            ASKPASS_MODE="askpass-setsid"
            return 0
        fi
    fi

    rm -f -- "$ASKPASS_FILE" 2>/dev/null
    rmdir -- "$ASKPASS_DIR" 2>/dev/null
    ASKPASS_FILE=""; ASKPASS_DIR=""
    return 1
}

# 选定密码注入后端：sshpass 优先，缺失时自动安装，装不上则零依赖降级
# 只在确实需要密码认证时调用（密钥可用时完全不需要准备后端）
ensure_auth_backend() {
    [[ -n $AUTH_BACKEND ]] && return 0

    if command -v sshpass >/dev/null 2>&1; then
        AUTH_BACKEND="sshpass"
        return 0
    fi

    warn "未检测到 sshpass（用于脚本内自动输入密码）。"
    local ans="n"
    if can_escalate; then
        IFS= read -r -p "是否尝试自动安装 sshpass？[Y=自动安装 / n=改用零依赖方案]: " ans || ans="n"
    else
        info "当前账号既不是 root 也没有 sudo，跳过自动安装。"
    fi

    if [[ ${ans:-Y} == [yY] ]]; then
        # 这里已经问过一次，装包不再重复确认
        if install_package sshpass yes && command -v sshpass >/dev/null 2>&1; then
            AUTH_BACKEND="sshpass"
            ok "sshpass 安装成功。"
            return 0
        fi
        err "sshpass 自动安装失败（软件源未更新、无网络或无权限）。"
    fi

    info "改用零第三方依赖方案：OpenSSH 自带的 SSH_ASKPASS 机制。"
    if ! setup_askpass; then
        err "当前 OpenSSH 版本过低且缺少可用的 setsid，无法启用零依赖方案。"
        err "请手动安装 sshpass：sudo apt-get install -y sshpass   （其他发行版见 README）"
        exit 1
    fi
    AUTH_BACKEND=$ASKPASS_MODE
    ok "已启用 ${ASKPASS_MODE} 模式，不再依赖 sshpass。"
}

ensure_deps() {
    # 1) ssh 客户端（必需，缺失时尝试自动安装）
    if ! command -v ssh >/dev/null 2>&1; then
        warn "未找到 ssh 客户端，尝试自动安装 OpenSSH 客户端 ……"
        local pm pkg="openssh"
        pm=$(detect_pm) || pm=""
        case $pm in
            apt-get) pkg="openssh-client" ;;
            dnf|yum|zypper) pkg="openssh-clients" ;;
        esac
        install_package "$pkg" >/dev/null || true
        command -v ssh >/dev/null 2>&1 || {
            err "无法自动安装 ssh 客户端。请手动安装后重试："
            err "  Debian/Ubuntu: sudo apt-get install -y openssh-client"
            err "  RHEL/CentOS  : sudo dnf install -y openssh-clients"
            err "  Arch         : sudo pacman -S openssh"
            exit 1
        }
        ok "ssh 客户端已就绪。"
    fi

    # 2) base64：远端路径全部经它编码后传递，本机缺失会让每条远端命令都拿到空路径，
    #    症状看起来像「远端缺 base64」，实际是本机的问题，所以在这里就拦住
    if ! command -v base64 >/dev/null 2>&1; then
        err "本机缺少 base64 命令，无法安全地把路径传给远端。"
        err "  Debian/Ubuntu: sudo apt-get install -y coreutils"
        err "  macOS 自带；其他发行版请安装 coreutils"
        exit 1
    fi

    # 3) 本机 HASH 工具：只探测一次，后续不再每文件 command -v
    detect_local_hasher || true

    # 4) 密码注入后端（sshpass 或零依赖 askpass）不在这里准备：
    #    先尝试密钥免密登录，确实需要密码时才初始化，避免多余装包

    # 5) 可选工具，只检测不安装：只影响进度显示效果，不影响功能
    command -v rsync >/dev/null 2>&1 && HAVE_RSYNC_LOCAL=1
    command -v pv    >/dev/null 2>&1 && HAVE_PV=1

    if (( HAVE_RSYNC_LOCAL == 1 )); then
        local ver
        ver=$(rsync --version 2>/dev/null | sed -n '1s/.*version[[:space:]]*\([0-9][0-9.]*\).*/\1/p')
        if [[ -n $ver ]] && [[ $(printf '%s\n%s\n' "3.1.0" "$ver" | sort -V 2>/dev/null | head -n 1) == "3.1.0" ]]; then
            RSYNC_INFO_OPT="--info=progress2"   # 3.1+ 才有总体进度 + 剩余时间
        else
            RSYNC_INFO_OPT="--progress"
        fi
    fi
}

#--------------------- SSH 相关封装 ---------------------
# 认证选项随认证方式变化：密钥可用时不再强制密码，反之禁用公钥以免反复弹密钥
refresh_auth_opts() {
    if (( USE_KEY_AUTH == 1 )); then
        SSH_AUTH_OPTS=(-o BatchMode=yes -o PasswordAuthentication=no -o NumberOfPasswordPrompts=0)
    else
        SSH_AUTH_OPTS=(-o PreferredAuthentications=password,keyboard-interactive
                       -o PubkeyAuthentication=no -o NumberOfPasswordPrompts=1)
    fi
}

# 统一的「带密码执行」封装：对外仍是 ssh/scp/rsync 的原始参数，
# 内部按当前后端决定注入方式，调用处无需关心用的是 sshpass 还是 askpass。
pw_run() {
    # 密钥认证：不需要任何密码注入，直接执行
    if (( USE_KEY_AUTH == 1 )); then
        "$@"
        return
    fi
    case $AUTH_BACKEND in
        sshpass)
            SSHPASS=$SSH_PASS sshpass -e "$@"
            ;;
        askpass-native)
            RTRANSFER_SSH_PASS=$SSH_PASS \
            SSH_ASKPASS=$ASKPASS_FILE \
            SSH_ASKPASS_REQUIRE=force \
            DISPLAY=${DISPLAY:-:0} \
                "$@"
            ;;
        askpass-setsid)
            RTRANSFER_SSH_PASS=$SSH_PASS \
            SSH_ASKPASS=$ASKPASS_FILE \
            DISPLAY=${DISPLAY:-:0} \
                setsid "$SETSID_FLAG" "$@"
            ;;
        *)
            err "内部错误：密码注入后端未初始化。"
            return 1
            ;;
    esac
}

# 执行一条远端命令；stdout 返回给调用者，stderr 收进 $TMP_ERR
# 每次调用先清空 $TMP_ERR，避免多轮重试后错误日志无限增长、互相污染
ssh_exec() {
    : > "$TMP_ERR" 2>/dev/null
    pw_run ssh \
        -p "$SSH_PORT" \
        -o "StrictHostKeyChecking=${SSH_HOSTKEY_OPT:-accept-new}" \
        -o ConnectTimeout="$SSH_CONNECT_TIMEOUT" \
        -o ServerAliveInterval=15 \
        -o ServerAliveCountMax=3 \
        -o LogLevel=ERROR \
        "${SSH_AUTH_OPTS[@]}" \
        -- "${SSH_USER}@${SSH_HOST}" "$1" 2>>"$TMP_ERR"
}

#--------------------- 主机密钥校验 ---------------------
# 首次连接必须由用户确认指纹后才继续，确认前不发送任何凭证。
# 已存在于 known_hosts 时用 yes（密钥变更即拒绝），而不是 accept-new 静默信任。
host_entry_name() {
    if (( SSH_PORT == 22 )); then
        printf '%s' "$SSH_HOST"
    else
        printf '[%s]:%s' "$SSH_HOST" "$SSH_PORT"
    fi
}

host_key_known() {
    command -v ssh-keygen >/dev/null 2>&1 || return 1
    [[ -f $KNOWN_HOSTS ]] || return 1
    ssh-keygen -F "$(host_entry_name)" -f "$KNOWN_HOSTS" >/dev/null 2>&1
}

# 抓取远端主机公钥（ssh-keyscan 不走认证，能安全地用于比对指纹）
fetch_host_keys() {
    command -v ssh-keyscan >/dev/null 2>&1 || return 1
    ssh-keyscan -T "$SSH_CONNECT_TIMEOUT" -p "$SSH_PORT" "$SSH_HOST" 2>/dev/null \
        | grep -v '^#' | grep -v '^[[:space:]]*$'
}

verify_host_key() {
    local keys fps ans

    if host_key_known; then
        SSH_HOSTKEY_OPT="yes"
        return 0
    fi

    if ! command -v ssh-keygen >/dev/null 2>&1 || ! command -v ssh-keyscan >/dev/null 2>&1; then
        err "缺少 ssh-keygen / ssh-keyscan，无法核对主机指纹。"
        err "请安装完整的 openssh-client 后重试。"
        return 1
    fi

    printf '\n'
    warn "首次连接 ${SSH_HOST}:${SSH_PORT}，需要确认远端主机密钥指纹。"
    keys=$(fetch_host_keys)
    if [[ -z $keys ]]; then
        err "无法获取远端主机密钥（ssh-keyscan 失败，可能被防火墙拦截或端口不通）。"
        err "为避免中间人攻击，脚本不会在未核对指纹的情况下继续。"
        printf '  可先手动确认再重试：ssh-keyscan -p %s %s >> ~/.ssh/known_hosts\n' \
            "$SSH_PORT" "$SSH_HOST"
        return 1
    fi

    fps=$(printf '%s\n' "$keys" | ssh-keygen -lf - 2>/dev/null | awk '{printf "    %-14s %s\n", $4, $2}')
    printf '  远端主机提供以下公钥：\n%s\n' "$fps"
    info "请与服务器管理员核对 SHA-256 指纹；核对无误后再继续。"

    while :; do
        IFS= read -r -p "  是否信任该主机并写入 known_hosts？[y=信任 / n=取消]: " ans || return 1
        case $ans in
            y|Y) break ;;
            n|N|"") err "已取消，未建立连接。"; return 1 ;;
            *) err "无效输入「$ans」：只能输入单个字母 y 或 n。" ;;
        esac
    done

    mkdir -p -- "$(dirname -- "$KNOWN_HOSTS")" 2>/dev/null || true
    chmod 700 -- "$(dirname -- "$KNOWN_HOSTS")" 2>/dev/null || true
    if ! printf '%s\n' "$keys" >> "$KNOWN_HOSTS"; then
        err "写入 known_hosts 失败：$KNOWN_HOSTS"
        return 1
    fi
    chmod 600 -- "$KNOWN_HOSTS" 2>/dev/null || true
    SSH_HOSTKEY_OPT="yes"
    ok "已记录主机密钥，后续连接将校验该指纹。"
    return 0
}

# 把 ssh 的报错翻译成人话
diagnose_ssh_error() {
    local msg=""
    if [[ -s $TMP_ERR ]]; then
        if   grep -qi 'permission denied' "$TMP_ERR"; then
            msg="密码错误，或该账号不允许密码登录"
        elif grep -qi 'connection refused' "$TMP_ERR"; then
            msg="端口未开放（SSH 服务未启动，或端口填错了）"
        elif grep -qiE 'timed out|no route to host|network is unreachable' "$TMP_ERR"; then
            msg="网络不可达或被防火墙拦截"
        elif grep -qi 'could not resolve hostname' "$TMP_ERR"; then
            msg="服务器地址无法解析，请检查域名或 IP"
        elif grep -qi 'host key verification failed' "$TMP_ERR"; then
            msg="主机密钥校验失败（远端主机密钥已变更）"
        elif grep -qi 'too many authentication failures' "$TMP_ERR"; then
            msg="认证失败次数过多，请稍后重试"
        else
            msg=$(head -n 2 "$TMP_ERR" | tr '\n' ' ')
        fi
    else
        msg="没有任何错误输出（可能是 sshpass 异常）"
    fi
    printf '%s' "$msg"
}

#--------------------- 第一步：采集连接信息 ---------------------
collect_ssh_info() {
    local raw ans

    printf '\n%s---- 第 1 步：SSH 连接信息 ----%s\n' "$C_BLD" "$C_RST"
    printf '  输入格式：地址:端口\n'
    printf '    例：192.168.1.10:22    example.com:2222    example.com    [2001:db8::1]:22\n'
    printf '  省略端口时默认使用 22；IPv4/IPv6 会做格式校验，域名不做校验。\n'

    while :; do
        IFS= read -r -p "远端地址:端口 : " raw || { printf '\n'; err "输入已结束，退出。"; exit 1; }
        raw=$(strip_quotes "$(trim "$raw")")

        if [[ -z $raw ]]; then
            err "输入不能为空，请按「地址:端口」的格式重新输入。"
            continue
        fi
        # 立即校验：格式不通过就不往下走，也不发起任何网络连接
        if ! parse_endpoint "$raw"; then
            err "格式错误：$PARSE_ERR"
            continue
        fi
        SSH_HOST=$HOST_PART
        SSH_PORT=$PORT_PART
        [[ -n $PARSE_NOTE ]] && info "$PARSE_NOTE"
        ok "远端地址：${SSH_HOST}（端口 ${SSH_PORT}）"

        # 主机指纹在输入用户名 / 密码之前确认，未确认就不发任何凭证
        if verify_host_key; then
            break
        fi
        IFS= read -r -p "是否重新输入地址？[Y=重新输入 / q=退出]: " ans || exit 1
        case ${ans:-Y} in
            q|Q) err "已取消，退出。"; exit 1 ;;
        esac
    done

    # 用户名只允许常规字符：它会被拼进 user@host，含空格或 @ 会让地址非法
    while :; do
        ask_required "SSH 用户名: "
        if [[ $REPLY_VALUE =~ ^[A-Za-z0-9._][A-Za-z0-9._-]*$ ]]; then
            SSH_USER=$REPLY_VALUE
            break
        fi
        err "用户名「$REPLY_VALUE」含非法字符：只允许字母、数字、点、下划线、连字符，且不能以 - 开头。"
    done
}

# 采集密码（仅在密钥认证不可用时）
ask_password() {
    while :; do
        IFS= read -r -s -p "SSH 密码（输入时不回显）: " SSH_PASS || { printf '\n'; err "输入已结束，退出。"; exit 1; }
        printf '\n'
        if [[ -n $SSH_PASS ]]; then
            return 0
        fi
        err "密码不能为空，请重新输入。"
    done
}

# 尝试连接并验证当前认证方式是否可用；$1 = quiet 时不打印「正在连接」
try_connect() {
    local out rc
    [[ ${1:-} == quiet ]] || info "正在连接 ${SSH_USER}@${SSH_HOST}:${SSH_PORT} ……"
    out=$(ssh_exec 'printf "__SSH_OK__\n"')
    rc=$?
    (( rc == 0 )) && [[ $out == *__SSH_OK__* ]]
}

# 先试公钥 / ssh-agent：能用就不必采集密码，也不必准备密码注入后端
try_key_auth() {
    USE_KEY_AUTH=1
    refresh_auth_opts
    if try_connect quiet; then
        return 0
    fi
    USE_KEY_AUTH=0
    refresh_auth_opts
    return 1
}

connect_loop() {
    local ans
    while :; do
        collect_ssh_info

        if try_key_auth; then
            ok "已通过公钥 / ssh-agent 免密登录，无需输入密码。"
            return 0
        fi

        ensure_auth_backend
        ask_password

        if try_connect; then
            ok "连接成功，密码校验通过。"
            return 0
        fi
        err "SSH 连接失败：$(diagnose_ssh_error)"
        printf '  远端详情（截取）：\n'
        [[ -s $TMP_ERR ]] && sed -n '1,3p' "$TMP_ERR" | sed 's/^/    /' >&2
        IFS= read -r -p "是否重新输入连接信息？[Y=重试 / q=退出]: " ans || exit 1
        case ${ans:-Y} in
            q|Q) err "已取消，退出。"; exit 1 ;;
            *)   unset SSHPASS 2>/dev/null; SSH_PASS="" ;;
        esac
    done
}

#--------------------- 第二步：本机源目录 ---------------------
choose_local_dir() {
    local raw abs

    printf '\n%s---- 第 2 步：选择要传输的本机文件夹 ----%s\n' "$C_BLD" "$C_RST"
    while :; do
        IFS= read -r -p "本机文件夹路径（支持空格，可直接粘贴）: " raw || { printf '\n'; exit 1; }
        raw=$(strip_quotes "$(trim "$raw")")

        # 手工展开 ~（read 不会自动展开）
        case $raw in
            "~")      raw=$HOME ;;
            "~/"*)    raw="$HOME/${raw#\~/}" ;;
        esac

        if [[ -z $raw ]]; then
            err "路径不能为空，请重新输入。"
            continue
        fi
        if [[ ! -e $raw ]]; then
            err "该路径不存在：$raw"
            continue
        fi
        if [[ ! -d $raw ]]; then
            err "该路径不是文件夹（可能是一个普通文件）：$raw"
            continue
        fi
        if [[ ! -r $raw ]]; then
            err "没有读取权限：$raw"
            continue
        fi
        if ! abs=$(cd -- "$raw" 2>/dev/null && pwd -P); then
            err "无法进入该目录（权限不足或路径异常）：$raw"
            continue
        fi
        if [[ $abs == "/" ]]; then
            err "不允许传输根目录 / ，请选择具体的文件夹。"
            continue
        fi
        if [[ -z $(ls -A -- "$abs" 2>/dev/null) ]]; then
            warn "该文件夹是空的，仍会继续传输。"
        fi

        LOCAL_ABS=$abs
        ok "源目录确认：$LOCAL_ABS"
        return 0
    done
}

#--------------------- 第三步：远端目标目录 ---------------------
# 结果放在 DIR_STATUS / DIR_MSG
DIR_STATUS=""
DIR_MSG=""

remote_ensure_dir() {
    local dir=$1 b64 out rc
    b64=$(to_b64 "$dir")

    out=$(ssh_exec "d=\$(printf '%s' '$b64' | base64 -d) || { echo __BADB64__; exit 9; }
if [ -d \"\$d\" ]; then
    if [ -w \"\$d\" ]; then echo __EXISTS__; else echo __NOWRITE__; fi
    exit 0
fi
if [ -e \"\$d\" ]; then echo __NOTDIR__; exit 3; fi
if e=\$(mkdir -p -- \"\$d\" 2>&1); then
    if [ -w \"\$d\" ]; then echo __CREATED__; else echo __NOWRITE__; fi
    exit 0
else
    echo \"__CREATEFAIL__ \$e\"; exit 4
fi")
    rc=$?
    DIR_MSG=""

    case $out in
        *__EXISTS__*)     DIR_STATUS="EXISTS" ;;
        *__CREATED__*)    DIR_STATUS="CREATED" ;;
        *__NOWRITE__*)    DIR_STATUS="NOWRITE" ;;
        *__NOTDIR__*)     DIR_STATUS="NOTDIR" ;;
        *__BADB64__*)     DIR_STATUS="BADB64" ;;
        *__CREATEFAIL__*) DIR_STATUS="FAILED"; DIR_MSG=${out#*__CREATEFAIL__ } ;;
        *)
            DIR_STATUS="UNKNOWN"
            if (( rc == 255 )); then
                DIR_MSG="SSH 连接中断：$(diagnose_ssh_error)"
            else
                DIR_MSG=${out:-"无输出，退出码 $rc"}
            fi
            ;;
    esac
}

choose_remote_dir() {
    local raw

    printf '\n%s---- 第 3 步：远端接收目录 ----%s\n' "$C_BLD" "$C_RST"
    while :; do
        IFS= read -r -p "远端目标路径（建议绝对路径，如 /data/backup）: " raw || { printf '\n'; exit 1; }
        raw=$(strip_quotes "$(trim "$raw")")

        if [[ -z $raw ]]; then
            err "路径不能为空，请重新输入。"
            continue
        fi
        # 去掉多余尾部斜杠，但保留根目录 /
        while [[ $raw == */ && $raw != "/" ]]; do
            raw=${raw%/}
        done
        if [[ $raw != /* ]]; then
            warn "未使用绝对路径，将相对远端用户的家目录处理：$raw"
        fi

        remote_ensure_dir "$raw"
        case $DIR_STATUS in
            EXISTS)
                ok "远端目录已存在：$raw"
                REMOTE_DIR=$raw
                return 0
                ;;
            CREATED)
                ok "远端目录不存在，已自动创建（含父目录）：$raw"
                REMOTE_DIR=$raw
                return 0
                ;;
            NOWRITE)
                err "远端目录存在但没有写权限：$raw"
                err "请换一个目录，或先在服务器上调整权限后重试。"
                ;;
            NOTDIR)
                err "远端该路径已存在，但不是一个目录：$raw"
                ;;
            BADB64)
                err "远端环境缺少 base64 命令，无法安全处理特殊字符路径。"
                return 1
                ;;
            FAILED)
                err "创建远端目录失败：$raw"
                [[ -n $DIR_MSG ]] && err "远端返回：$DIR_MSG"
                err "常见原因：上级目录无权限、磁盘已满、只读文件系统。"
                ;;
            *)
                err "无法确认远端目录状态：$raw"
                [[ -n $DIR_MSG ]] && err "详情：$DIR_MSG"
                ;;
        esac
    done
}

#--------------------- 第四步：传输 ---------------------
build_ssh_e() {
    local s
    s="ssh -p $SSH_PORT -o StrictHostKeyChecking=${SSH_HOSTKEY_OPT:-accept-new} -o LogLevel=ERROR"
    s+=" -o ConnectTimeout=$SSH_CONNECT_TIMEOUT"
    # 弱网 / 半开连接下避免长时间挂住
    s+=" -o ServerAliveInterval=15 -o ServerAliveCountMax=3"
    if (( USE_KEY_AUTH == 1 )); then
        s+=" -o BatchMode=yes -o PasswordAuthentication=no"
    else
        s+=" -o PreferredAuthentications=password,keyboard-interactive"
        s+=" -o PubkeyAuthentication=no -o NumberOfPasswordPrompts=1"
    fi
    printf '%s' "$s"
}

# 远端是否可用 rsync
check_remote_rsync() {
    local out rc
    out=$(ssh_exec 'command -v rsync >/dev/null 2>&1 && printf "__HAS_RSYNC__\n"')
    rc=$?
    if [[ $out == *__HAS_RSYNC__* ]]; then
        HAVE_RSYNC_REMOTE=1
        return 0
    fi
    HAVE_RSYNC_REMOTE=0
    # 退出码 1 表示远端确实没装 rsync；其他值多为连接 / 认证异常，不能静默降级
    if (( rc != 0 && rc != 1 )); then
        warn "探测远端 rsync 失败（退出码 $rc：$(diagnose_ssh_error)），将改用其他传输方式。"
        return 1
    fi
    return 0
}

# 远端路径能否安全地直接交给 scp：
# OpenSSH 9.0 之前（或加 -O 时）scp 的远端路径由远端 shell 解析，
# 含空格 / 通配符 / 命令替换等字符会被二次解释，这种情况改用 tar 管道。
remote_path_is_scp_safe() {
    case $1 in
        -*|"")                            return 1 ;;
        *[[:space:]]*)                    return 1 ;;
        *'`'*|*'$'*|*';'*|*'&'*|*'|'*)    return 1 ;;
        *'*'*|*'?'*|*'['*|*']'*)          return 1 ;;
        *'<'*|*'>'*|*'!'*|*'~'*)          return 1 ;;
        *"'"*|*'"'*|*'\'*)                return 1 ;;
        *'('*|*')'*|*'{'*|*'}'*)          return 1 ;;
    esac
    return 0
}

# 远端 tar 是否为 GNU tar（决定「不覆盖」用哪个参数）
remote_tar_is_gnu() {
    local out
    out=$(ssh_exec 'tar --version 2>/dev/null | head -n 1')
    [[ $out == *GNU* ]]
}

# tar 管道传输；$1 = pv（带 pv 进度）或 plain（无进度）
tar_transfer() {
    local mode=$1 base rd_b64 total pv_args remote_tar_cmd x_opts rc
    local -a pst
    base=$(basename -- "$LOCAL_ABS")
    rd_b64=$(to_b64 "$REMOTE_DIR")

    x_opts=""
    if (( OVERWRITE == 0 )); then
        if remote_tar_is_gnu; then
            x_opts="--skip-old-files"
        else
            warn "远端不是 GNU tar，改用 -k：已有的文件不会被覆盖，但部分实现遇到同名文件会报错。"
            x_opts="-k"
        fi
    fi

    remote_tar_cmd="d=\$(printf '%s' '$rd_b64' | base64 -d) || exit 9; cd -- \"\$d\" || exit 8; tar $x_opts -xf -"
    printf '\n'
    if [[ $mode == "pv" ]]; then
        total=$(du -sb -- "$LOCAL_ABS" 2>/dev/null | awk '{print $1}')
        if [[ -z ${total:-} ]]; then
            total=$(du -sk -- "$LOCAL_ABS" 2>/dev/null | awk '{print $1 * 1024}')
        fi
        pv_args=(-p -t -e -r -b)
        [[ -n ${total:-} ]] && pv_args+=(-s "$total")

        ( cd -- "$(dirname -- "$LOCAL_ABS")" && tar -cf - -- "$base" ) \
            | pv "${pv_args[@]}" \
            | ssh_exec "$remote_tar_cmd"
        pst=("${PIPESTATUS[@]}")
    else
        ( cd -- "$(dirname -- "$LOCAL_ABS")" && tar -cf - -- "$base" ) \
            | ssh_exec "$remote_tar_cmd"
        pst=("${PIPESTATUS[@]}")
    fi
    # 三环（tar / pv / ssh）里任一环失败都算失败：只看最后一环会把
    # 「本机 tar 读文件失败但远端正常收尾」误判成传输成功
    rc=$(worst_rc "${pst[@]}")
    TAR_RC_DETAIL=""
    (( rc != 0 )) && TAR_RC_DETAIL="${pst[*]}"
    return "$rc"
}

do_transfer() {
    local base dest_path dest ssh_e rc rsync_opts

    base=$(basename -- "$LOCAL_ABS")
    FINAL_DIR=$(join_path "$REMOTE_DIR" "$base")
    if [[ $REMOTE_DIR == "/" ]]; then
        dest_path="/"
    else
        dest_path="${REMOTE_DIR}/"
    fi
    dest="${SSH_USER}@$(host_for_remote):${dest_path}"
    ssh_e=$(build_ssh_e)

    printf '\n%s---- 第 4 步：开始传输 ----%s\n' "$C_BLD" "$C_RST"
    info "本机源目录 : $LOCAL_ABS"
    info "远端目标   : ${SSH_USER}@${SSH_HOST}:${REMOTE_DIR}"
    info "传输后将生成：$FINAL_DIR"
    if (( OVERWRITE == 1 )); then
        info "覆盖策略   : 覆盖远端同名文件"
    else
        info "覆盖策略   : 跳过远端已存在的文件（不覆盖）"
    fi

    if (( HAVE_RSYNC_LOCAL == 1 )); then
        check_remote_rsync
    fi

    if (( HAVE_RSYNC_LOCAL == 1 && HAVE_RSYNC_REMOTE == 1 )); then
        # RSYNC_INFO_OPT 可能是空串（版本探测失败时），不能当成一个空参数传给 rsync，
        # 否则 rsync 会把它当作一个空的源路径而直接报错
        rsync_opts=(-a --human-readable --stats -s)
        [[ -n $RSYNC_INFO_OPT ]] && rsync_opts+=("$RSYNC_INFO_OPT")
        if (( OVERWRITE == 0 )); then
            # --partial 会把中断残留的半截文件留在目标位置，配上 --ignore-existing
            # 就被当成「已存在」永久跳过，坏文件再也修不回来；不覆盖模式下不用它
            rsync_opts+=(--ignore-existing)
        else
            rsync_opts+=(--partial)
        fi
        info "传输方式：rsync（下方实时显示进度、当前速度与预计剩余时间）"
        printf '\n'
        pw_run rsync "${rsync_opts[@]}" -e "$ssh_e" -- "$LOCAL_ABS" "$dest"
        rc=$?
    elif (( HAVE_PV == 1 )); then
        info "传输方式：tar + pv（实时显示速度与预计剩余时间）"
        tar_transfer pv
        rc=$?
    elif (( OVERWRITE == 0 )); then
        warn "本机没有 rsync / pv，而 scp 无法跳过已存在文件，改用 tar 管道执行「不覆盖」。"
        info "传输方式：tar + ssh（无进度显示）"
        tar_transfer plain
        rc=$?
    elif ! remote_path_is_scp_safe "$REMOTE_DIR"; then
        warn "远端路径含空格或特殊字符，scp 会把它交给远端 shell 解析，可能被二次解释。"
        info "传输方式：tar + ssh（无进度显示，但路径经 base64 传递，不做 shell 解析）"
        tar_transfer plain
        rc=$?
    else
        warn "本机与远端都没有 rsync，且本机未安装 pv。"
        warn "改用 scp 传输，此方式无法显示实时速度与剩余时间。"
        printf '\n'
        pw_run scp -r -p -P "$SSH_PORT" \
            -o "StrictHostKeyChecking=${SSH_HOSTKEY_OPT:-accept-new}" \
            -o ConnectTimeout="$SSH_CONNECT_TIMEOUT" \
            -o ServerAliveInterval=15 \
            -o ServerAliveCountMax=3 \
            "${SSH_AUTH_OPTS[@]}" \
            -o LogLevel=ERROR \
            -- "$LOCAL_ABS" "$dest"
        rc=$?
    fi

    printf '\n'
    if (( rc == 0 )); then
        ok "传输完成。"
    elif (( rc == 24 )); then
        warn "传输基本完成，但有文件在传输过程中消失（rsync 退出码 24）。"
    elif (( rc == 255 )); then
        err "传输失败：SSH 连接中断。"
        err "详情：$(diagnose_ssh_error)"
        exit 1
    else
        err "传输失败，退出码 $rc。"
        [[ -n ${TAR_RC_DETAIL:-} ]] && \
            err "tar 管道各环节退出码：$TAR_RC_DETAIL（顺序为 tar / pv / ssh）"
        [[ -s $TMP_ERR ]] && sed -n '1,3p' "$TMP_ERR" | sed 's/^/    /' >&2
        err "已安全退出，本机文件未做任何修改。"
        exit 1
    fi
}

#--------------------- 收尾汇总 ---------------------
print_summary() {
    local remote_size fb64
    [[ -z $FINAL_DIR ]] && FINAL_DIR=$(join_path "$REMOTE_DIR" "$(basename -- "$LOCAL_ABS")")
    fb64=$(to_b64 "$FINAL_DIR")

    remote_size=$(ssh_exec "d=\$(printf '%s' '$fb64' | base64 -d) || exit 9
if [ -d \"\$d\" ]; then du -sh -- \"\$d\" 2>/dev/null | cut -f1; else echo '__MISSING__'; fi")

    printf '\n%s==============================================================%s\n' "$C_BLD" "$C_RST"
    if [[ $HASH_STATUS == "DIFF" ]]; then
        err "传输已完成，但源与目标的 HASH 不一致，请核对上方差异明细。"
    elif [[ $HASH_STATUS == "ERROR" ]]; then
        warn "传输已完成，但 HASH 校验未能完成。"
    else
        ok "全部完成"
    fi
    printf '  本机源目录 ：%s\n' "$LOCAL_ABS"
    printf '  远端主机   ：%s@%s（端口 %s）\n' "$SSH_USER" "$SSH_HOST" "$SSH_PORT"
    printf '  远端目标   ：%s\n' "$REMOTE_DIR"
    printf '  最终路径   ：%s\n' "$FINAL_DIR"
    if [[ $remote_size == *__MISSING__* || -z $remote_size ]]; then
        warn "远端未查询到该目录，请手工确认。"
    else
        printf '  远端占用   ：%s\n' "$remote_size"
    fi

    case $HASH_STATUS in
        SAME)
            printf '  HASH 校验  ：%s一致%s（本机 %d 个文件 / 远端 %d 个文件）\n' \
                "$C_GRN" "$C_RST" "$HASH_COUNT_LOCAL" "$HASH_COUNT_REMOTE"
            printf '    本机 SHA-256：%s\n' "$HASH_LOCAL"
            printf '    远端 SHA-256：%s\n' "$HASH_REMOTE"
            printf '    （汇总值 = 全部文件「相对路径 + 内容 SHA-256」清单的 SHA-256）\n'
            ;;
        DIFF)
            printf '  HASH 校验  ：%s不一致%s（本机 %d 个文件 / 远端 %d 个文件）\n' \
                "$C_RED" "$C_RST" "$HASH_COUNT_LOCAL" "$HASH_COUNT_REMOTE"
            printf '    本机 SHA-256：%s\n' "$HASH_LOCAL"
            printf '    远端 SHA-256：%s\n' "$HASH_REMOTE"
            if [[ -n $HASH_DIFF ]]; then
                printf '    差异明细（< 本机侧 / > 远端侧；内容不同时两侧各列一行）：\n'
                printf '%s\n' "$HASH_DIFF" | sed 's/^/      /'
            fi
            if (( OVERWRITE == 0 )); then
                warn "本次选择了「不覆盖」：远端已有同名文件保留旧内容，HASH 差异可能由此产生。"
            fi
            ;;
        SKIPPED)
            printf '  HASH 校验  ：已跳过（未执行）\n'
            ;;
        *)
            printf '  HASH 校验  ：未能完成\n'
            [[ -n $HASH_MSG ]] && printf '    原因：%s\n' "$HASH_MSG"
            ;;
    esac
    printf '%s==============================================================%s\n' "$C_BLD" "$C_RST"
}

#--------------------- 覆盖策略（传输前统一询问一次） ---------------------
ask_overwrite() {
    local ans
    printf '\n%s---- 第 3.5 步：覆盖策略 ----%s\n' "$C_BLD" "$C_RST"
    while :; do
        IFS= read -r -p "远端已存在同名文件时是否覆盖？[y=覆盖 / n=不覆盖]: " ans || { printf '\n'; exit 1; }
        # 严格匹配单个字母，多余字符（含空格）、空输入、其他字符一律要求重输
        case $ans in
            y|Y)
                OVERWRITE=1
                ok "已选择：覆盖远端同名文件。"
                return 0
                ;;
            n|N)
                OVERWRITE=0
                ok "已选择：跳过已存在的文件，不覆盖。"
                return 0
                ;;
            "")
                err "输入不能为空，只能输入单个字母 y 或 n。"
                ;;
            *)
                err "无效输入“$ans”：只能输入单个字母 y 或 n（大小写均可），不能包含空格或其他字符。"
                ;;
        esac
    done
}

#--------------------- 第五步：HASH 校验 ---------------------
# 逐文件比对 SHA-256 清单；只比内容，不比权限 / 属主 / 时间戳 / 空目录
HASH_STATUS="SKIPPED"       # SKIPPED 跳过 / SAME 一致 / DIFF 不一致 / ERROR 未完成
HASH_LOCAL=""
HASH_REMOTE=""
HASH_COUNT_LOCAL=0
HASH_COUNT_REMOTE=0
HASH_DIFF=""
HASH_MSG=""

# 本机可用的 SHA-256 工具：启动时只探测一次，避免每个文件重复 command -v
detect_local_hasher() {
    if command -v sha256sum >/dev/null 2>&1; then
        HASHER_LOCAL="sha256sum"
    elif command -v shasum >/dev/null 2>&1; then
        HASHER_LOCAL="shasum"
    elif command -v openssl >/dev/null 2>&1; then
        HASHER_LOCAL="openssl"
    else
        HASHER_LOCAL=""
        return 1
    fi
    return 0
}

# 对标准输入求 SHA-256（用于清单汇总值）
hash_stream() {
    case $HASHER_LOCAL in
        sha256sum) sha256sum | cut -d' ' -f1 ;;
        shasum)    shasum -a 256 | cut -d' ' -f1 ;;
        openssl)   openssl dgst -sha256 | awk '{print $NF}' ;;
        *)         return 1 ;;
    esac
}

# 把各家的 `hash<分隔符>./path` 统一成 `hash  path`，让两侧清单逐字节可比。
# 需要消化三种实现差异，任何一条漏掉都会变成「内容其实一致却报不一致」：
#   1) GNU coreutils 遇到文件名含反斜杠/换行时，会在行首加 \ 做转义
#   2) 二进制模式下哈希与路径之间是 " *"（星号），不是两个空格
#   3) 路径前缀 ./ 需要去掉，使两侧相对路径同形
manifest_clean() {
    sed -e 's/^\\//' \
        -e 's/^\([0-9a-fA-F]\{64\}\)[[:space:]][[:space:]]*[*]\{0,1\}/\1  /' \
        -e 's/^\([0-9a-fA-F]\{64\}\)  \.\//\1  /'
}

# 生成「哈希  相对路径」清单（按路径排序，保证两侧可比）
# 用 find -exec ... + 批量调用，避免每个文件 fork 一次哈希进程
local_manifest() {
    local f h
    case $HASHER_LOCAL in
        sha256sum)
            ( cd -- "$LOCAL_ABS" 2>/dev/null || exit 1
              find . -type f -exec sha256sum {} + 2>/dev/null | manifest_clean
            ) | LC_ALL=C sort -k2
            ;;
        shasum)
            ( cd -- "$LOCAL_ABS" 2>/dev/null || exit 1
              find . -type f -exec shasum -a 256 {} + 2>/dev/null | manifest_clean
            ) | LC_ALL=C sort -k2
            ;;
        openssl)
            # openssl 没有批量模式，只能逐文件；路径来自 find，带 ./ 前缀
            ( cd -- "$LOCAL_ABS" 2>/dev/null || exit 1
              find . -type f -print0 2>/dev/null | while IFS= read -r -d '' f; do
                  h=$(openssl dgst -sha256 "$f" 2>/dev/null | sed 's/.*= //')
                  [[ -n $h ]] || exit 1
                  printf '%s  %s\n' "$h" "${f#./}"
              done
            ) | LC_ALL=C sort -k2
            ;;
        *)
            return 1
            ;;
    esac
}

# 在远端生成同样的清单；路径经 base64 传递，避免二次解释。
# 远端刻意只用 POSIX sh 语法：ssh 用远端登录 shell 执行命令，
# dash / busybox ash 不支持 bash 的 read -d、数组与 [[ ]]，写了就必然失败。
remote_manifest() {
    local b64
    b64=$(to_b64 "$FINAL_DIR")
    ssh_exec "B64='$b64'
d=\$(printf '%s' \"\$B64\" | base64 -d) || { echo __BADB64__; exit 9; }
cd -- \"\$d\" 2>/dev/null || { echo __NODIR__; exit 8; }
if command -v sha256sum >/dev/null 2>&1; then
    find . -type f -exec sha256sum {} + 2>/dev/null
elif command -v shasum >/dev/null 2>&1; then
    find . -type f -exec shasum -a 256 {} + 2>/dev/null
elif command -v openssl >/dev/null 2>&1; then
    find . -type f | while IFS= read -r f; do
        h=\$(openssl dgst -sha256 \"\$f\" 2>/dev/null | sed 's/.*= //')
        if [ -z \"\$h\" ]; then echo __HASHFAIL__; exit 1; fi
        printf '%s  %s\n' \"\$h\" \"\${f#./}\"
    done
else
    echo __NOHASH__; exit 7
fi" | manifest_clean | LC_ALL=C sort -k2
}

do_hash_verify() {
    local rrc

    if [[ -z $HASHER_LOCAL ]]; then
        HASH_STATUS="ERROR"
        HASH_MSG="本机没有 sha256sum / shasum / openssl，无法计算 HASH。"
        err "$HASH_MSG"
        return 0
    fi

    info "正在计算本机源目录的 HASH ……"
    # 清单落到临时文件，避免十万级文件时整份列表驻留内存
    if ! local_manifest > "$TMP_MAN_L"; then
        HASH_STATUS="ERROR"
        HASH_MSG="计算本机清单失败：有文件读不出来，或目录不可访问。"
        err "$HASH_MSG"
        return 0
    fi
    if [[ ! -s $TMP_MAN_L ]]; then
        HASH_STATUS="ERROR"
        HASH_MSG="本机源目录内没有普通文件（空目录无法比对）。"
        err "$HASH_MSG"
        return 0
    fi

    info "正在计算远端目标目录的 HASH ……"
    remote_manifest > "$TMP_MAN_R"
    rrc=$?

    # 远端用哨兵值报告具体原因，先按哨兵判断，再看退出码
    if grep -qx '__NOHASH__' "$TMP_MAN_R"; then
        HASH_STATUS="ERROR"; HASH_MSG="远端缺少 sha256sum / shasum / openssl，无法计算 HASH。"
        err "$HASH_MSG"; return 0
    fi
    if grep -qx '__NODIR__' "$TMP_MAN_R"; then
        HASH_STATUS="ERROR"; HASH_MSG="远端目标目录不存在或无法进入：$FINAL_DIR"
        err "$HASH_MSG"; return 0
    fi
    if grep -qx '__BADB64__' "$TMP_MAN_R"; then
        HASH_STATUS="ERROR"; HASH_MSG="远端缺少 base64，无法安全传递目录名。"
        err "$HASH_MSG"; return 0
    fi
    if grep -qx '__HASHFAIL__' "$TMP_MAN_R"; then
        HASH_STATUS="ERROR"; HASH_MSG="远端有文件读不出来，清单不完整。"
        err "$HASH_MSG"; return 0
    fi
    if (( rrc != 0 )); then
        HASH_STATUS="ERROR"
        HASH_MSG="远端清单生成失败（退出码 $rrc）：$(diagnose_ssh_error)"
        err "$HASH_MSG"
        return 0
    fi
    if [[ ! -s $TMP_MAN_R ]]; then
        HASH_STATUS="ERROR"; HASH_MSG="远端目标目录内没有普通文件。"
        err "$HASH_MSG"; return 0
    fi

    HASH_COUNT_LOCAL=$(grep -c . "$TMP_MAN_L")
    HASH_COUNT_REMOTE=$(grep -c . "$TMP_MAN_R")
    HASH_LOCAL=$(hash_stream < "$TMP_MAN_L")
    HASH_REMOTE=$(hash_stream < "$TMP_MAN_R")
    # 两侧都算不出汇总值时不能直接比较：两个空串相等会被误判成「一致」
    if [[ -z $HASH_LOCAL || -z $HASH_REMOTE ]]; then
        HASH_STATUS="ERROR"
        HASH_MSG="汇总值计算失败：本机 SHA-256 工具不可用（HASHER_LOCAL=${HASHER_LOCAL:-无}）。"
        err "$HASH_MSG"
        return 0
    fi

    if [[ $HASH_LOCAL == "$HASH_REMOTE" ]]; then
        HASH_STATUS="SAME"
    else
        HASH_STATUS="DIFF"
        HASH_DIFF=$(diff "$TMP_MAN_L" "$TMP_MAN_R" 2>/dev/null | head -n 30)
    fi
    return 0
}

ask_hash_verify() {
    local ans
    printf '\n%s---- 第 5 步：HASH 校验 ----%s\n' "$C_BLD" "$C_RST"
    printf '  将对源目录与远端目标目录中的每个文件计算 SHA-256 并逐一比对；\n'
    printf '  只比对文件内容，不比对权限、属主、时间戳与空目录。\n'
    while :; do
        IFS= read -r -p "是否执行 HASH 校验？[Y=执行 / n=跳过]: " ans ||
            { printf '\n'; HASH_STATUS="SKIPPED"; return 0; }
        # 与覆盖询问保持一致：只认单个字母，" y " 这种带空格的也算无效
        case $ans in
            ""|y|Y) do_hash_verify; return 0 ;;
            n|N)    HASH_STATUS="SKIPPED"; info "已跳过 HASH 校验。"; return 0 ;;
            *)      err "无效输入「$ans」：请输入单个字母 y 执行校验，或 n 跳过（直接回车默认执行）。" ;;
        esac
    done
}

#--------------------- 主流程 ---------------------
main() {
    print_banner
    ensure_deps
    connect_loop
    choose_local_dir
    choose_remote_dir || exit 1
    ask_overwrite
    do_transfer
    ask_hash_verify
    print_summary
    # HASH 校验结果用独立退出码告知调用者：
    # 2 = 内容不一致；3 = 校验没能完成（既不能算通过，也不该算一致）
    if [[ $HASH_STATUS == "DIFF" ]]; then
        exit 2
    fi
    if [[ $HASH_STATUS == "ERROR" ]]; then
        exit 3
    fi
    return 0
}

# 只在直接执行时进入主流程；被 source 时仅加载函数，便于单元测试
if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
    main "$@"
fi
