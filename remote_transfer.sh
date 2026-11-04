#!/usr/bin/env bash
#=====================================================================
#  remote_transfer.sh —— 交互式 SSH 远端文件夹传输助手
#
#  功能：
#    1. 交互式采集 SSH 地址 / 用户名 / 端口 / 密码，并逐项校验非空
#    2. 实际建立 SSH 连接以验证密码是否正确，失败可重新输入
#    3. 校验本机源目录（存在 / 是目录 / 可读），循环直到有效
#    4. 检查远端目标目录，不存在则 mkdir -p 自动创建（含多级父目录）
#    5. rsync 传输，实时显示进度、速度与预计剩余时间
#    6. 传输前统一询问一次「是否覆盖已存在文件」，该选择作用于本次全部传输
#    7. 依赖自检：缺 sshpass 时尝试自动安装，装不上则降级为 OpenSSH
#       自带的 SSH_ASKPASS 方案（零第三方依赖）
#
#  依赖：ssh（必需）；sshpass（可选，缺失时自动安装或零依赖降级）；
#        rsync / pv（可选，仅影响速度与剩余时间的显示效果）
#
#  用法： bash remote_transfer.sh
#=====================================================================
set -uo pipefail

#--------------------- 全局变量 ---------------------
SSH_HOST=""
SSH_USER=""
SSH_PORT=""
SSH_PASS=""
SSH_CONNECT_TIMEOUT=10      # 单次连接超时（秒）

LOCAL_ABS=""                # 本机源目录的绝对路径
REMOTE_DIR=""                # 远端目标目录
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

TMP_ERR="$(mktemp "${TMPDIR:-/tmp}/rtransfer.XXXXXX" 2>/dev/null)" || {
    printf '无法创建临时文件，脚本退出。\n' >&2
    exit 1
}

#--------------------- 清理与信号 ---------------------
cleanup() {
    unset SSHPASS RTRANSFER_SSH_PASS 2>/dev/null || true
    [[ -n "${TMP_ERR:-}" && -f "$TMP_ERR" ]] && rm -f -- "$TMP_ERR"
    # askpass 辅助脚本里不含密码，只做删除；失败也不影响退出
    if [[ -n "${ASKPASS_FILE:-}" && -f "$ASKPASS_FILE" ]]; then
        : > "$ASKPASS_FILE" 2>/dev/null
        rm -f -- "$ASKPASS_FILE" 2>/dev/null || true
        if [[ -n "${ASKPASS_DIR:-}" && -d "$ASKPASS_DIR" ]]; then
            rmdir -- "$ASKPASS_DIR" 2>/dev/null || true
        fi
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

validate_port() {
    local p=$1
    [[ $p =~ ^[0-9]{1,5}$ ]] || return 1
    (( 10#$p >= 1 && 10#$p <= 65535 ))
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

install_package() {
    local pkg=$1 pm
    pm=$(detect_pm) || { err "未识别到可用的包管理器，无法自动安装 $pkg。"; return 1; }

    info "正在通过 $pm 安装 $pkg ……"
    case $pm in
        apt-get) DEBIAN_FRONTEND=noninteractive as_root apt-get install -y "$pkg" ;;
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
    ASKPASS_DIR=$(mktemp -d "${TMPDIR:-/tmp}/rtransfer.askpass.XXXXXX" 2>/dev/null) || return 1
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
ensure_auth_backend() {
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
        if install_package sshpass && command -v sshpass >/dev/null 2>&1; then
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
        install_package "$pkg" >/dev/null 2>&1 || true
        command -v ssh >/dev/null 2>&1 || {
            err "无法自动安装 ssh 客户端。请手动安装后重试："
            err "  Debian/Ubuntu: sudo apt-get install -y openssh-client"
            err "  RHEL/CentOS  : sudo dnf install -y openssh-clients"
            err "  Arch         : sudo pacman -S openssh"
            exit 1
        }
        ok "ssh 客户端已就绪。"
    fi

    # 2) 密码注入后端（sshpass 或零依赖 askpass）
    ensure_auth_backend

    # 3) 可选工具，只检测不安装：只影响进度显示效果，不影响功能
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
# 统一的「带密码执行」封装：对外仍是 ssh/scp/rsync 的原始参数，
# 内部按当前后端决定注入方式，调用处无需关心用的是 sshpass 还是 askpass。
pw_run() {
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
ssh_exec() {
    pw_run ssh \
        -p "$SSH_PORT" \
        -o StrictHostKeyChecking=accept-new \
        -o ConnectTimeout="$SSH_CONNECT_TIMEOUT" \
        -o ServerAliveInterval=15 \
        -o ServerAliveCountMax=3 \
        -o NumberOfPasswordPrompts=1 \
        -o PreferredAuthentications=password,keyboard-interactive \
        -o PubkeyAuthentication=no \
        -o LogLevel=ERROR \
        -- "${SSH_USER}@${SSH_HOST}" "$1" 2>>"$TMP_ERR"
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
    printf '\n%s---- 第 1 步：SSH 连接信息 ----%s\n' "$C_BLD" "$C_RST"

    ask_required "远端服务器地址（IP 或域名）: "
    SSH_HOST=$REPLY_VALUE

    ask_required "SSH 用户名: "
    SSH_USER=$REPLY_VALUE

    while :; do
        ask_required "SSH 端口（1-65535，默认端口请填 22）: "
        if validate_port "$REPLY_VALUE"; then
            SSH_PORT=$REPLY_VALUE
            break
        fi
        err "端口必须是 1-65535 之间的数字，您输入的是：$REPLY_VALUE"
    done

    while :; do
        IFS= read -r -s -p "SSH 密码（输入时不回显）: " SSH_PASS || { printf '\n'; err "输入已结束，退出。"; exit 1; }
        printf '\n'
        if [[ -n $SSH_PASS ]]; then
            break
        fi
        err "密码不能为空，请重新输入。"
    done
}

# 尝试连接并校验密码
try_connect() {
    local out rc
    : > "$TMP_ERR"

    info "正在连接 ${SSH_USER}@${SSH_HOST}:${SSH_PORT} ……"
    out=$(ssh_exec 'printf "__SSH_OK__\n"')
    rc=$?

    if (( rc == 0 )) && [[ $out == *__SSH_OK__* ]]; then
        return 0
    fi
    return 1
}

connect_loop() {
    local ans
    while :; do
        collect_ssh_info
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
    printf 'ssh -p %s -o StrictHostKeyChecking=accept-new -o LogLevel=ERROR' "$SSH_PORT"
    printf ' -o PreferredAuthentications=password,keyboard-interactive'
    printf ' -o PubkeyAuthentication=no -o ConnectTimeout=%s' "$SSH_CONNECT_TIMEOUT"
}

# 远端是否可用 rsync
check_remote_rsync() {
    local out
    out=$(ssh_exec 'command -v rsync >/dev/null 2>&1 && printf "__HAS_RSYNC__\n"')
    [[ $out == *__HAS_RSYNC__* ]] && HAVE_RSYNC_REMOTE=1 || HAVE_RSYNC_REMOTE=0
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
        rc=${PIPESTATUS[2]}
    else
        ( cd -- "$(dirname -- "$LOCAL_ABS")" && tar -cf - -- "$base" ) \
            | ssh_exec "$remote_tar_cmd"
        rc=${PIPESTATUS[1]}
    fi
    return "$rc"
}

do_transfer() {
    local base dest_path dest ssh_e rc rsync_opts

    base=$(basename -- "$LOCAL_ABS")
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
    info "传输后将生成：$(join_path "$REMOTE_DIR" "$base")"
    if (( OVERWRITE == 1 )); then
        info "覆盖策略   : 覆盖远端同名文件"
    else
        info "覆盖策略   : 跳过远端已存在的文件（不覆盖）"
    fi

    if (( HAVE_RSYNC_LOCAL == 1 )); then
        check_remote_rsync
    fi

    if (( HAVE_RSYNC_LOCAL == 1 && HAVE_RSYNC_REMOTE == 1 )); then
        rsync_opts=(-a --partial --human-readable "$RSYNC_INFO_OPT" --stats -s)
        if (( OVERWRITE == 0 )); then
            rsync_opts+=(--ignore-existing)   # 跳过接收端已存在的文件
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
    else
        warn "本机与远端都没有 rsync，且本机未安装 pv。"
        warn "改用 scp 传输，此方式无法显示实时速度与剩余时间。"
        printf '\n'
        pw_run scp -r -p -P "$SSH_PORT" \
            -o StrictHostKeyChecking=accept-new \
            -o PreferredAuthentications=password,keyboard-interactive \
            -o PubkeyAuthentication=no \
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
        [[ -s $TMP_ERR ]] && sed -n '1,3p' "$TMP_ERR" | sed 's/^/    /' >&2
        err "已安全退出，本机文件未做任何修改。"
        exit 1
    fi
}

#--------------------- 收尾汇总 ---------------------
print_summary() {
    local final fb64 remote_size
    final=$(join_path "$REMOTE_DIR" "$(basename -- "$LOCAL_ABS")")
    fb64=$(to_b64 "$final")

    remote_size=$(ssh_exec "d=\$(printf '%s' '$fb64' | base64 -d) || exit 9
if [ -d \"\$d\" ]; then du -sh -- \"\$d\" 2>/dev/null | cut -f1; else echo '__MISSING__'; fi")

    printf '\n%s==============================================================%s\n' "$C_BLD" "$C_RST"
    ok "全部完成"
    printf '  本机源目录 ：%s\n' "$LOCAL_ABS"
    printf '  远端主机   ：%s@%s（端口 %s）\n' "$SSH_USER" "$SSH_HOST" "$SSH_PORT"
    printf '  远端目标   ：%s\n' "$REMOTE_DIR"
    printf '  最终路径   ：%s\n' "$final"
    if [[ $remote_size == *__MISSING__* || -z $remote_size ]]; then
        warn "远端未查询到该目录，请手工确认。"
    else
        printf '  远端占用   ：%s\n' "$remote_size"
    fi
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

#--------------------- 主流程 ---------------------
main() {
    print_banner
    ensure_deps
    connect_loop
    choose_local_dir
    choose_remote_dir || exit 1
    ask_overwrite
    do_transfer
    print_summary
}

main "$@"
