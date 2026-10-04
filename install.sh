#!/usr/bin/env bash
set -Eeuo pipefail
umask 027

PREFIX=${SBM_WEB_PREFIX:-/usr/local}
LIB_DIR=${SBM_WEB_LIB:-$PREFIX/lib/sb-manager-web}
BIN_DIR=${SBM_WEB_BIN:-$PREFIX/bin}
ETC_DIR=${SBM_WEB_ETC:-/etc/sb-manager-web}
VAR_DIR=${SBM_WEB_VAR:-/var/lib/sb-manager-web}
LOG_DIR=${SBM_WEB_LOG:-/var/log/sb-manager-web}
SYSTEMD_DIR=${SBM_WEB_SYSTEMD_DIR:-/etc/systemd/system}
OPENRC_DIR=${SBM_WEB_OPENRC_DIR:-/etc/init.d}
PERIODIC_DIR=${SBM_WEB_PERIODIC_DIR:-/etc/periodic}
SERVICE_USER=${SBM_WEB_SERVICE_USER:-sbweb}
VERSION=${SBM_WEB_VERSION:-latest}
REPO=${SBM_WEB_REPO:-ridd1e1337/sb-manager-web}
SB_INSTALL_URL=${SBM_WEB_SB_INSTALL_URL:-https://raw.githubusercontent.com/ridd1e1337/sb-manager/main/install.sh}
INIT_SYSTEM=${SBM_WEB_INIT_SYSTEM:-auto}
PANEL_TLS_MODE=${SBM_WEB_TLS_MODE:-auto}
PANEL_TLS_DOMAIN=${SBM_WEB_TLS_DOMAIN:-}
PANEL_TLS_EMAIL=${SBM_WEB_TLS_EMAIL:-}
PANEL_TLS_CERT_FILE=${SBM_WEB_TLS_CERT_FILE:-}
PANEL_TLS_KEY_FILE=${SBM_WEB_TLS_KEY_FILE:-}
PANEL_TLS_CF_TOKEN=${SBM_WEB_TLS_CF_TOKEN:-}
PANEL_TLS_CF_ZONE_ID=${SBM_WEB_TLS_CF_ZONE_ID:-}
PANEL_LISTEN=${SBM_WEB_LISTEN:-127.0.0.1:9091}
PANEL_PUBLIC_IPV4=${SBM_WEB_PUBLIC_IPV4:-}
PANEL_ACME_HOME=${SBM_WEB_ACME_HOME:-$VAR_DIR/acme-panel}
PANEL_ACME_COMMIT=${SBM_WEB_ACME_COMMIT:-3661fd86b6304115e42f43910e6dd452ab9866d6}
PANEL_ACME_SHA256=${SBM_WEB_ACME_SHA256:-9af3ad3d775a5782246df4cdd4b4e7b9b3179deb63c509b10e3ba0433093a884}
panel_listen_override=0
if [[ -n ${SBM_WEB_LISTEN+x} ]]; then panel_listen_override=1; fi
NO_START=0
UPDATE_ONLY=0
AGENT_CONTROLLER=''
AGENT_TOKEN=''
initial_credential_output=''
panel_tls_enabled=0
panel_acme_enabled=0
panel_acme_bin=''

usage() {
  cat <<'EOF'
用法：sudo ./install.sh [--version VERSION] [--no-start]
      sudo ./install.sh --update-only [--version VERSION]
      sudo ./install.sh --agent CONTROLLER_URL ENROLLMENT_TOKEN
      sudo ./install.sh --panel-tls MODE [--panel-domain DOMAIN] [--panel-email EMAIL]

环境变量：
  SBM_WEB_BINARY_URL       直接指定二进制地址
  SBM_WEB_CHECKSUM_URL     SHA256SUMS 地址
  SBM_WEB_SKIP_VERIFY=1    跳过摘要校验（仅开发环境）
  SBM_WEB_PREFIX/LIB/ETC/VAR/LOG  覆盖安装路径
  SBM_WEB_SB_INSTALL_URL   sb-manager 独立安装器地址
  SBM_WEB_AUTO_INSTALL_SB=0  禁用缺失依赖时的自动安装
  SBM_WEB_INIT_SYSTEM      强制 systemd/openrc（默认自动检测）
  SBM_WEB_TLS_MODE         auto/self-signed/acme-http/acme-dns-cloudflare/existing
  SBM_WEB_TLS_DOMAIN       面板证书的域名或 IP
  SBM_WEB_TLS_EMAIL        可选 ACME 联系邮箱
  SBM_WEB_TLS_CERT_FILE/KEY_FILE  已有证书和私钥绝对路径（existing）
  SBM_WEB_TLS_CF_TOKEN/ZONE_ID    Cloudflare DNS-01 凭据
  SBM_WEB_PUBLIC_IPV4       覆盖自动探测到的公网 IPv4
  SBM_WEB_LISTEN           面板监听地址（默认 127.0.0.1:9091）

命令行证书选项：
  --panel-tls MODE          选择面板 TLS 流程
  --panel-domain DOMAIN     证书域名或 IP
  --panel-email EMAIL       可选 ACME 联系邮箱
  --panel-cert PATH         已有证书链绝对路径
  --panel-key PATH          已有私钥绝对路径
  --panel-cf-token TOKEN    Cloudflare API Token
  --panel-cf-zone-id ID     Cloudflare Zone ID（可选）
  --panel-listen ADDRESS    覆盖面板监听地址

--agent 会安装二进制、完成一次性注册并只启动 Agent 服务。
EOF
}

install_sb_manager() {
  local installer_dir installer rc=0
  installer_dir=$(mktemp -d)
  installer="$installer_dir/install.sh"
  printf '未发现 sb-manager，正在通过独立项目安装器自动安装…\n'
  if [[ -f "$SB_INSTALL_URL" ]]; then
    cp -p "$SB_INSTALL_URL" "$installer"
  elif curl --fail --silent --show-error --location \
    --retry 3 --retry-delay 2 --connect-timeout 15 \
    --proto '=https' --tlsv1.2 "$SB_INSTALL_URL" -o "$installer"; then
    :
  else
    rc=$?
    rm -rf "$installer_dir"
    return "$rc"
  fi
  if [[ "$NO_START" == 1 ]]; then
    if bash "$installer" --no-menu --no-start; then :; else rc=$?; fi
  elif bash "$installer" --no-menu; then
    :
  else
    rc=$?
  fi
  rm -rf "$installer_dir"
  [[ "$rc" == 0 ]] || return "$rc"
  hash -r
  command -v sb >/dev/null 2>&1 || {
    echo 'sb-manager 安装器执行完成，但 PATH 中仍未找到 sb。' >&2
    return 1
  }
}

detect_init_system() {
  case "$INIT_SYSTEM" in
    systemd|openrc|none) printf '%s\n' "$INIT_SYSTEM"; return 0;;
    auto) ;;
    *) echo "SBM_WEB_INIT_SYSTEM 无效：$INIT_SYSTEM" >&2; return 1;;
  esac
  if [[ -d /run/systemd/system ]] && command -v systemctl >/dev/null 2>&1; then
    printf 'systemd\n'
  elif command -v rc-update >/dev/null 2>&1 \
    && command -v rc-service >/dev/null 2>&1 \
    && { [[ -e /run/openrc/softlevel ]] || command -v openrc-run >/dev/null 2>&1; }; then
    printf 'openrc\n'
  else
    printf 'none\n'
  fi
}

cleanup_legacy_openrc_services() {
  local name path
  for name in sb-manager-web sb-manager-web-helper sb-manager-web-agent; do
    path="$OPENRC_DIR/$name"
    [[ -f "$path" ]] || continue
    if grep -Fqx '#!/sbin/openrc-run' "$path" \
      && grep -Fq 'sb-manager' "$path" \
      && grep -Fq 'WebUI' "$path" \
      && grep -Fq 'sb-web' "$path"; then
      rm -f "$path"
      printf '已清理 systemd 主机上旧版误写的 OpenRC 服务：%s\n' "$path"
    fi
  done
}

service_user_can_execute_web() {
  local command
  if [[ "$SERVICE_USER" == root ]]; then
    "$BIN_DIR/sb-web" version >/dev/null
  elif command -v runuser >/dev/null 2>&1; then
    runuser -u "$SERVICE_USER" -- "$BIN_DIR/sb-web" version >/dev/null
  elif command -v su >/dev/null 2>&1; then
    printf -v command '%q version' "$BIN_DIR/sb-web"
    su -s /bin/sh "$SERVICE_USER" -c "$command" >/dev/null
  else
    return 0
  fi
}

panel_has_tty() {
  [[ -t 0 || -t 1 || -t 2 ]]
}

panel_read_tty() {
  local prompt=$1 secret=${2:-0} value=''
  printf '%s' "$prompt" >/dev/tty
  if [[ "$secret" == 1 ]]; then
    IFS= read -r -s value </dev/tty
    printf '\n' >/dev/tty
  else
    IFS= read -r value </dev/tty
  fi
  printf '%s' "$value"
}

panel_choose_tls_mode() {
  [[ "$PANEL_TLS_MODE" == auto ]] || return 0
  [[ -n "$AGENT_CONTROLLER" ]] && { PANEL_TLS_MODE=none; return 0; }
  if ! panel_has_tty; then
    if command -v jq >/dev/null 2>&1 && [[ -s "$ETC_DIR/config.json" ]] \
      && [[ $(jq -r '.tls.enabled // false' "$ETC_DIR/config.json" 2>/dev/null) == true ]]; then
      PANEL_TLS_CERT_FILE=$(jq -r '.tls.cert_file // empty' "$ETC_DIR/config.json")
      PANEL_TLS_KEY_FILE=$(jq -r '.tls.key_file // empty' "$ETC_DIR/config.json")
      if [[ -s "$PANEL_TLS_CERT_FILE" && -s "$PANEL_TLS_KEY_FILE" ]]; then
        PANEL_TLS_MODE=existing
        return 0
      fi
    fi
    echo '控制端面板强制使用 HTTPS；非交互首次安装请指定 --panel-tls 和相应证书参数。' >&2
    return 1
  fi
  {
    printf '\n面板强制使用 HTTPS，请选择证书方式：\n'
    printf '  1) 自动申请本机公网 IPv4 证书（默认）\n'
    printf '  2) 申请域名证书\n'
    printf '  3) 生成自签名证书（适合内网，浏览器会提示不受信任）\n'
    printf '  4) 使用已有证书和私钥（输入绝对路径）\n'
    printf '请选择 [1-4]：'
  } >/dev/tty
  local choice
  choice=$(panel_read_tty '' 0)
  case "$choice" in
    2) PANEL_TLS_MODE=acme-domain;;
    3) PANEL_TLS_MODE=self-signed;;
    4) PANEL_TLS_MODE=existing;;
    *)
      PANEL_TLS_MODE=acme-http
      PANEL_TLS_DOMAIN=$(panel_public_ipv4 || true)
      [[ -n "$PANEL_TLS_DOMAIN" ]] || {
        echo '无法自动探测公网 IPv4；请重新运行并选择域名证书，或设置 SBM_WEB_PUBLIC_IPV4。' >&2
        return 1
      }
      ;;
  esac
}

panel_is_ipv4() {
  local value=$1 octet
  local -a octets
  [[ "$value" =~ ^[0-9]+(\.[0-9]+){3}$ ]] || return 1
  IFS=. read -r -a octets <<<"$value"
  ((${#octets[@]} == 4)) || return 1
  for octet in "${octets[@]}"; do
    [[ "$octet" =~ ^[0-9]{1,3}$ ]] || return 1
    ((10#$octet <= 255)) || return 1
  done
}

panel_is_ip() {
  panel_is_ipv4 "$1" || { [[ "$1" == *:* && "$1" =~ ^[0-9A-Fa-f:.]+$ ]]; }
}

panel_public_ipv4() {
  local candidate url
  if [[ -n "$PANEL_PUBLIC_IPV4" ]]; then
    panel_is_ipv4 "$PANEL_PUBLIC_IPV4" || return 1
    printf '%s\n' "$PANEL_PUBLIC_IPV4"
    return 0
  fi
  if command -v curl >/dev/null 2>&1; then
    candidate=$(curl -4fsS --noproxy '*' --connect-timeout 1 --max-time 2 \
      'http://169.254.169.254/latest/meta-data/public-ipv4' 2>/dev/null || true)
    if panel_is_ipv4 "$candidate"; then
      printf '%s\n' "$candidate"
      return 0
    fi
    for url in https://api.ipify.org https://ifconfig.me/ip https://ipv4.icanhazip.com; do
      candidate=$(curl -4fsS --connect-timeout 2 --max-time 3 --proto '=https' --tlsv1.2 "$url" 2>/dev/null | tr -d '[:space:]' || true)
      if panel_is_ipv4 "$candidate"; then
        printf '%s\n' "$candidate"
        return 0
      fi
    done
  fi
  return 1
}

panel_normalize_email() {
  local email=$1 local_part domain
  email=${email//$'\r'/}
  email=${email//$'\n'/}
  email=${email//$'\t'/}
  email=${email// /}
  email=${email//$'\u00a0'/}
  email=${email//$'\u200b'/}
  local_part=${email%@*}
  domain=${email##*@}
  [[ "$local_part" != "$email" ]] || { printf '%s\n' "$email"; return 0; }
  printf '%s@%s\n' "$local_part" "${domain,,}"
}

panel_clear_saved_acme_contacts() {
  local file
  [[ -d "$PANEL_ACME_HOME/config" ]] || return 0
  while IFS= read -r file; do
    sed -i '/^ACCOUNT_EMAIL=/d; /^CA_EMAIL=/d' "$file"
  done < <(find "$PANEL_ACME_HOME/config" -type f \( -name account.conf -o -name ca.conf \) -print 2>/dev/null)
}

panel_default_identifier() {
  local address=''
  address=$(panel_public_ipv4 || true)
  [[ -n "$address" ]] && { printf '%s\n' "$address"; return 0; }
  if command -v ip >/dev/null 2>&1; then
    address=$(ip route get 1.1.1.1 2>/dev/null | awk '{for (i=1; i<=NF; i++) if ($i == "src") {print $(i+1); exit}}')
  fi
  if [[ -z "$address" ]] && command -v hostname >/dev/null 2>&1; then
    address=$(hostname -I 2>/dev/null | awk '{print $1}')
  fi
  printf '%s\n' "${address:-127.0.0.1}"
}

panel_validate_identifier() {
  local identifier=$1
  if panel_is_ip "$identifier"; then
    return 0
  fi
  [[ "$identifier" =~ ^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$ ]] || {
    echo "面板证书标识符无效：$identifier" >&2
    return 1
  }
}

panel_current_port() {
  local listen_value port
  listen_value="$PANEL_LISTEN"
  if command -v jq >/dev/null 2>&1 && [[ -s "$ETC_DIR/config.json" ]]; then
    listen_value=$(jq -r '.listen // empty' "$ETC_DIR/config.json" 2>/dev/null || true)
    [[ -n "$listen_value" ]] || listen_value="$PANEL_LISTEN"
  fi
  port=${listen_value##*:}
  if [[ ! "$port" =~ ^[0-9]+$ ]] || ((port < 1 || port > 65535)); then port=9091; fi
  printf '%s\n' "$port"
}

panel_enable_public_listen_for_ip() {
  panel_is_ipv4 "$PANEL_TLS_DOMAIN" || return 0
  ((panel_listen_override == 0)) || return 0
  PANEL_LISTEN="0.0.0.0:$(panel_current_port)"
  panel_listen_override=1
  printf '已为公网 IP 证书自动设置面板监听：%s\n' "$PANEL_LISTEN"
}

panel_collect_tls_inputs() {
  local detected_ip email_domain email_tld
  case "$PANEL_TLS_MODE" in
    none)
      [[ -n "$AGENT_CONTROLLER" ]] && return 0
      echo '控制端面板不允许关闭 HTTPS。' >&2
      return 1
      ;;
    auto)
      echo '无法确定 HTTPS 证书配置。' >&2
      return 1
      ;;
    self-signed)
      [[ -n "$PANEL_TLS_DOMAIN" ]] || PANEL_TLS_DOMAIN=$(panel_default_identifier)
      ;;
    acme-auto|acme-domain|acme-http|acme-dns-cloudflare)
      if [[ -z "$PANEL_TLS_DOMAIN" ]]; then
        panel_has_tty || { echo 'ACME 流程需要 --panel-domain 或 SBM_WEB_TLS_DOMAIN。' >&2; return 1; }
        if [[ "$PANEL_TLS_MODE" == acme-auto ]]; then
          detected_ip=$(panel_public_ipv4 || true)
          printf '\n自动申请证书：\n' >/dev/tty
          if [[ -n "$detected_ip" ]]; then
            printf '  1) 使用本机公网 IPv4（检测到：%s）\n' "$detected_ip" >/dev/tty
          else
            printf '  1) 使用本机公网 IPv4（当前未检测到，可稍后手动指定）\n' >/dev/tty
          fi
          printf '  2) 输入域名\n请选择 [1-2]：' >/dev/tty
          case "$(panel_read_tty '' 0)" in
            1)
              PANEL_TLS_DOMAIN="$detected_ip"
              [[ -n "$PANEL_TLS_DOMAIN" ]] || {
                echo '无法自动探测公网 IPv4，请选择域名或设置 SBM_WEB_PUBLIC_IPV4。' >&2
                return 1
              }
              ;;
            *) PANEL_TLS_DOMAIN=$(panel_read_tty '面板域名：');;
          esac
        else
          detected_ip=$(panel_public_ipv4 || true)
          if [[ -n "$detected_ip" ]]; then
            PANEL_TLS_DOMAIN=$(panel_read_tty "面板域名或 IP（直接回车使用 $detected_ip）：")
            [[ -n "$PANEL_TLS_DOMAIN" ]] || PANEL_TLS_DOMAIN="$detected_ip"
          else
            PANEL_TLS_DOMAIN=$(panel_read_tty '面板域名或 IP（输入 IP 将自动探测公网 IPv4）：')
          fi
        fi
      fi
      case "${PANEL_TLS_DOMAIN,,}" in
        ip|public-ip|公网ip|公网-ip)
          PANEL_TLS_DOMAIN=$(panel_public_ipv4 || true)
          [[ -n "$PANEL_TLS_DOMAIN" ]] || {
            echo '无法自动探测公网 IPv4，请改用 --panel-domain 指定地址或设置 SBM_WEB_PUBLIC_IPV4。' >&2
            return 1
          }
          ;;
      esac
      if [[ -z "$PANEL_TLS_DOMAIN" ]]; then
        echo '面板域名或 IP 不能为空。' >&2
        return 1
      fi
      panel_validate_identifier "$PANEL_TLS_DOMAIN" || return 1
      if [[ "$PANEL_TLS_MODE" == acme-domain ]]; then
        panel_is_ip "$PANEL_TLS_DOMAIN" && { echo '域名证书选项不能输入 IP；公网 IP 证书请使用默认选项 1。' >&2; return 1; }
        panel_has_tty || { echo '域名证书需要选择 HTTP-01 或 Cloudflare DNS-01。' >&2; return 1; }
        printf '1) HTTP-01（需要公网 80 端口）\n2) Cloudflare DNS-01（支持泛域名）\n请选择 [1-2]：' >/dev/tty
        case "$(panel_read_tty '' 0)" in
          2) PANEL_TLS_MODE=acme-dns-cloudflare;;
          *) PANEL_TLS_MODE=acme-http;;
        esac
      fi
      if [[ "$PANEL_TLS_MODE" == acme-auto ]]; then
        if panel_is_ip "$PANEL_TLS_DOMAIN"; then
          PANEL_TLS_MODE=acme-http
        else
          panel_has_tty || { echo '自动 ACME 流程需要选择 HTTP-01 或 Cloudflare DNS-01。' >&2; return 1; }
          printf '1) HTTP-01（需要公网 80 端口）\n2) Cloudflare DNS-01（支持泛域名）\n请选择 [1-2]：' >/dev/tty
          case "$(panel_read_tty '' 0)" in
            2) PANEL_TLS_MODE=acme-dns-cloudflare;;
            *) PANEL_TLS_MODE=acme-http;;
          esac
        fi
      fi
      [[ "$PANEL_TLS_MODE" != acme-dns-cloudflare ]] && panel_enable_public_listen_for_ip
      if [[ "$PANEL_TLS_MODE" == acme-dns-cloudflare ]] && panel_is_ip "$PANEL_TLS_DOMAIN"; then
        echo 'Cloudflare DNS-01 不能为 IP 标识申请证书；IP 证书请使用 acme-http 流程。' >&2
        return 1
      fi
      if [[ -n "$PANEL_TLS_EMAIL" ]]; then
        PANEL_TLS_EMAIL=$(panel_normalize_email "$PANEL_TLS_EMAIL")
        email_domain=${PANEL_TLS_EMAIL##*@}
        email_tld=${email_domain##*.}
        [[ "$PANEL_TLS_EMAIL" =~ ^[^[:space:]@]+@[^[:space:]@]+\.[^[:space:]@]+$ && "$email_tld" =~ ^[A-Za-z0-9-]{2,63}$ ]] || {
          echo 'ACME 账户邮箱格式无效；请使用真实公共域名邮箱，或不填写邮箱。' >&2
          return 1
        }
        printf '使用 ACME 账户邮箱：%s\n' "$PANEL_TLS_EMAIL"
      else
        printf 'ACME 联系邮箱：未设置（可选，不影响证书签发）\n'
      fi
      if [[ "$PANEL_TLS_MODE" == acme-dns-cloudflare && -z "$PANEL_TLS_CF_TOKEN" ]]; then
        panel_has_tty || { echo 'Cloudflare DNS-01 需要 --panel-cf-token 或 SBM_WEB_TLS_CF_TOKEN。' >&2; return 1; }
        PANEL_TLS_CF_TOKEN=$(panel_read_tty 'Cloudflare API Token（输入不会回显）：' 1)
      fi
      ;;
    existing)
      if [[ -z "$PANEL_TLS_CERT_FILE" ]]; then
        panel_has_tty || { echo 'existing 流程需要 --panel-cert 或 SBM_WEB_TLS_CERT_FILE 指定证书绝对路径。' >&2; return 1; }
        PANEL_TLS_CERT_FILE=$(panel_read_tty '证书链绝对路径：')
      fi
      if [[ -z "$PANEL_TLS_KEY_FILE" ]]; then
        panel_has_tty || { echo 'existing 流程需要 --panel-key 或 SBM_WEB_TLS_KEY_FILE 指定私钥绝对路径。' >&2; return 1; }
        PANEL_TLS_KEY_FILE=$(panel_read_tty '私钥绝对路径：')
      fi
      [[ "$PANEL_TLS_CERT_FILE" == /* && -f "$PANEL_TLS_CERT_FILE" ]] || {
        echo "证书路径必须是存在的绝对路径：$PANEL_TLS_CERT_FILE" >&2
        return 1
      }
      [[ "$PANEL_TLS_KEY_FILE" == /* && -f "$PANEL_TLS_KEY_FILE" ]] || {
        echo "私钥路径必须是存在的绝对路径：$PANEL_TLS_KEY_FILE" >&2
        return 1
      }
      ;;
    *)
      echo "面板 TLS 模式无效：$PANEL_TLS_MODE（可用 auto、self-signed、acme-http、acme-dns-cloudflare、existing）" >&2
      return 1
      ;;
  esac
}

panel_tls_paths() {
  PANEL_TLS_DIR="$ETC_DIR/tls"
  PANEL_TLS_CERT_PATH="$PANEL_TLS_DIR/fullchain.pem"
  PANEL_TLS_KEY_PATH="$PANEL_TLS_DIR/key.pem"
}

panel_install_acme() {
  local tmpdir archive source actual
  local -a install_args
  panel_acme_bin="$PANEL_ACME_HOME/acme.sh"
  [[ -x "$panel_acme_bin" ]] && return 0
  command -v tar >/dev/null 2>&1 || { echo 'ACME 流程需要 tar。' >&2; return 1; }
  tmpdir=$(mktemp -d)
  archive="$tmpdir/acme.tar.gz"
  curl --fail --silent --show-error --location --retry 3 --retry-delay 2 \
    --connect-timeout 15 --proto '=https' --tlsv1.2 \
    "https://github.com/acmesh-official/acme.sh/archive/$PANEL_ACME_COMMIT.tar.gz" -o "$archive"
  actual=$(sha256sum "$archive" | awk '{print $1}')
  [[ "$actual" == "$PANEL_ACME_SHA256" ]] || {
    echo 'acme.sh 下载摘要不匹配，已拒绝执行。' >&2
    rm -rf "$tmpdir"
    return 1
  }
  mkdir -p "$tmpdir/src"
  tar -xzf "$archive" -C "$tmpdir/src" --strip-components=1
  source="$tmpdir/src/acme.sh"
  [[ -f "$source" ]] || { echo 'acme.sh 安装包不完整。' >&2; rm -rf "$tmpdir"; return 1; }
  mkdir -p "$PANEL_ACME_HOME"
  install_args=(--install --home "$PANEL_ACME_HOME" --config-home "$PANEL_ACME_HOME/config" --cert-home "$PANEL_ACME_HOME/certs" --nocron --noprofile)
  [[ -z "$PANEL_TLS_EMAIL" ]] || install_args+=(--accountemail "$PANEL_TLS_EMAIL")
  (
    cd "$tmpdir/src"
    bash ./acme.sh "${install_args[@]}"
  )
  rm -rf "$tmpdir"
  [[ -x "$panel_acme_bin" ]] || { echo 'acme.sh 安装失败。' >&2; return 1; }
  chmod 0700 "$PANEL_ACME_HOME"
}

panel_register_acme_account() {
  local account_args=(--home "$PANEL_ACME_HOME" --config-home "$PANEL_ACME_HOME/config" --cert-home "$PANEL_ACME_HOME/certs" --server letsencrypt)
  panel_clear_saved_acme_contacts
  [[ -z "$PANEL_TLS_EMAIL" ]] || account_args+=(--accountemail "$PANEL_TLS_EMAIL")
  if [[ -n "$PANEL_TLS_EMAIL" ]]; then
    printf '正在注册 ACME 账户并验证联系邮箱…\n'
  else
    printf '正在注册 ACME 账户（未设置联系邮箱）…\n'
  fi
  "$panel_acme_bin" "${account_args[@]}" --register-account || {
    echo 'ACME 账户注册失败；面板配置未修改。' >&2
    return 1
  }
  if [[ -n "$PANEL_TLS_EMAIL" ]]; then
    "$panel_acme_bin" "${account_args[@]}" --update-account || {
      echo 'ACME 账户联系邮箱更新失败；面板配置未修改。' >&2
      return 1
    }
  fi
}

panel_validate_certificate_pair() {
  local cert=$1 key=$2 cert_pub key_pub
  [[ -s "$cert" && -s "$key" ]] || { echo '面板证书或私钥文件为空。' >&2; return 1; }
  openssl x509 -in "$cert" -noout >/dev/null 2>&1 || { echo '面板证书 PEM 无效。' >&2; return 1; }
  openssl pkey -in "$key" -noout >/dev/null 2>&1 || { echo '面板私钥 PEM 无效或需要密码。' >&2; return 1; }
  cert_pub=$(openssl x509 -in "$cert" -pubkey -noout 2>/dev/null | openssl pkey -pubin -outform DER 2>/dev/null | sha256sum | awk '{print $1}')
  key_pub=$(openssl pkey -in "$key" -pubout -outform DER 2>/dev/null | sha256sum | awk '{print $1}')
  [[ -n "$cert_pub" && "$cert_pub" == "$key_pub" ]] || { echo '面板证书与私钥不匹配。' >&2; return 1; }
}

panel_copy_certificate_pair() {
  local cert=$1 key=$2
  panel_validate_certificate_pair "$cert" "$key" || return 1
  mkdir -p "$PANEL_TLS_DIR"
  chmod 0750 "$PANEL_TLS_DIR"
  install -m 0644 "$cert" "$PANEL_TLS_CERT_PATH.new"
  install -m 0640 "$key" "$PANEL_TLS_KEY_PATH.new"
  mv -f "$PANEL_TLS_CERT_PATH.new" "$PANEL_TLS_CERT_PATH"
  mv -f "$PANEL_TLS_KEY_PATH.new" "$PANEL_TLS_KEY_PATH"
}

panel_self_signed_certificate() {
  local tmpdir san_type
  panel_validate_identifier "$PANEL_TLS_DOMAIN" || return 1
  tmpdir=$(mktemp -d)
  if panel_is_ip "$PANEL_TLS_DOMAIN"; then san_type=IP; else san_type=DNS; fi
  openssl req -x509 -newkey rsa:2048 -nodes -days 825 \
    -subj "/CN=$PANEL_TLS_DOMAIN" \
    -addext "subjectAltName=$san_type:$PANEL_TLS_DOMAIN" \
    -keyout "$tmpdir/key.pem" -out "$tmpdir/fullchain.pem" >/dev/null 2>&1
  panel_copy_certificate_pair "$tmpdir/fullchain.pem" "$tmpdir/key.pem"
  rm -rf "$tmpdir"
}

panel_write_reload_hook() {
  PANEL_CERT_RELOAD_HOOK="$LIB_DIR/reload-panel-certificate"
  install -m 0755 /dev/stdin "$PANEL_CERT_RELOAD_HOOK" <<EOF_PANEL_RELOAD
#!/bin/sh
set -eu
cert_new='$PANEL_TLS_CERT_PATH.new'
key_new='$PANEL_TLS_KEY_PATH.new'
cert='$PANEL_TLS_CERT_PATH'
key='$PANEL_TLS_KEY_PATH'
if [ -s "\$cert_new" ] && [ -s "\$key_new" ]; then
  cert_pub=\$(openssl x509 -in "\$cert_new" -pubkey -noout 2>/dev/null | openssl pkey -pubin -outform DER 2>/dev/null | sha256sum | awk '{print \$1}')
  key_pub=\$(openssl pkey -in "\$key_new" -pubout -outform DER 2>/dev/null | sha256sum | awk '{print \$1}')
  [ -n "\$cert_pub" ] && [ "\$cert_pub" = "\$key_pub" ]
  chmod 0644 "\$cert_new"
  chmod 0640 "\$key_new"
  chown root:$SERVICE_USER "\$cert_new" "\$key_new" 2>/dev/null || true
  mv -f "\$cert_new" "\$cert"
  mv -f "\$key_new" "\$key"
fi
if [ ! -f '$PANEL_ACME_HOME/panel-deploying' ] && [ -f '$PANEL_ACME_HOME/panel-certificate' ] && [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then
  systemctl try-restart sb-manager-web.service >/dev/null 2>&1 || true
elif [ ! -f '$PANEL_ACME_HOME/panel-deploying' ] && [ -f '$PANEL_ACME_HOME/panel-certificate' ] && command -v rc-service >/dev/null 2>&1; then
  rc-service sb-manager-web restart >/dev/null 2>&1 || true
fi
EOF_PANEL_RELOAD
}

panel_acme_certificate() {
  local issue_args=() cert_new key_new reload_cmd issue_rc=0 install_rc=0
  panel_install_acme || return 1
  panel_register_acme_account || return 1
  issue_args=(--home "$PANEL_ACME_HOME" --config-home "$PANEL_ACME_HOME/config" --cert-home "$PANEL_ACME_HOME/certs" --issue -d "$PANEL_TLS_DOMAIN" --server letsencrypt --keylength ec-256)
  [[ -z "$PANEL_TLS_EMAIL" ]] || issue_args+=(--accountemail "$PANEL_TLS_EMAIL")
  if [[ "$PANEL_TLS_MODE" == acme-dns-cloudflare ]]; then
    export CF_Token="$PANEL_TLS_CF_TOKEN"
    [[ -n "$PANEL_TLS_CF_ZONE_ID" ]] && export CF_Zone_ID="$PANEL_TLS_CF_ZONE_ID"
    issue_args+=(--dns dns_cf)
  else
    issue_args+=(--standalone)
  fi
  if panel_is_ip "$PANEL_TLS_DOMAIN"; then
    issue_args+=(--cert-profile shortlived)
  fi
  if "$panel_acme_bin" "${issue_args[@]}"; then
    :
  else
    issue_rc=$?
    [[ "$issue_rc" == 2 ]] || return "$issue_rc"
    printf '现有证书尚未到续期时间，继续部署当前有效证书。\n'
  fi
  mkdir -p "$PANEL_TLS_DIR"
  panel_write_reload_hook
  cert_new="$PANEL_TLS_CERT_PATH.new"
  key_new="$PANEL_TLS_KEY_PATH.new"
  reload_cmd=$(printf '%q' "$PANEL_CERT_RELOAD_HOOK")
  touch "$PANEL_ACME_HOME/panel-deploying"
  if "$panel_acme_bin" --home "$PANEL_ACME_HOME" --config-home "$PANEL_ACME_HOME/config" --cert-home "$PANEL_ACME_HOME/certs" \
    --install-cert -d "$PANEL_TLS_DOMAIN" --ecc --fullchain-file "$cert_new" --key-file "$key_new" \
    --reloadcmd "$reload_cmd"; then
    :
  else
    install_rc=$?
    rm -f "$PANEL_ACME_HOME/panel-deploying"
    return "$install_rc"
  fi
  panel_validate_certificate_pair "$PANEL_TLS_CERT_PATH" "$PANEL_TLS_KEY_PATH" || {
    rm -f "$PANEL_ACME_HOME/panel-deploying"
    return 1
  }
  panel_activate_tls_config || {
    rm -f "$PANEL_ACME_HOME/panel-deploying"
    return 1
  }
  touch "$PANEL_ACME_HOME/panel-certificate"
  rm -f "$PANEL_ACME_HOME/panel-deploying"
  unset CF_Token CF_Zone_ID
  panel_acme_enabled=1
}

panel_activate_tls_config() {
  local tmpcfg
  command -v jq >/dev/null 2>&1 || { echo '配置面板 TLS 需要 jq。' >&2; return 1; }
  tmpcfg=$(mktemp "$ETC_DIR/.config.XXXXXX")
  jq --arg cert "$PANEL_TLS_CERT_PATH" --arg key "$PANEL_TLS_KEY_PATH" --arg listen "$PANEL_LISTEN" --argjson update_listen "$panel_listen_override" \
    '.tls.enabled=true | .tls.cert_file=$cert | .tls.key_file=$key | if $update_listen == 1 then .listen=$listen else . end' \
    "$ETC_DIR/config.json" >"$tmpcfg"
  chmod 0600 "$tmpcfg"
  mv -f "$tmpcfg" "$ETC_DIR/config.json"
  panel_tls_enabled=1
}

panel_tls_setup() {
  panel_choose_tls_mode
  panel_collect_tls_inputs || return 1
  panel_tls_paths
  if [[ "$PANEL_TLS_MODE" != none && "$PANEL_TLS_MODE" != auto ]]; then
    command -v jq >/dev/null 2>&1 || { echo '面板 TLS 流程需要 jq。' >&2; return 1; }
    command -v openssl >/dev/null 2>&1 || { echo '面板 TLS 流程需要 openssl。' >&2; return 1; }
  fi
  case "$PANEL_TLS_MODE" in
    none|auto) return 0;;
    self-signed) panel_self_signed_certificate;;
    acme-http|acme-dns-cloudflare) panel_acme_certificate; return $?;;
    existing) panel_copy_certificate_pair "$PANEL_TLS_CERT_FILE" "$PANEL_TLS_KEY_FILE";;
  esac
  panel_activate_tls_config
}

panel_validate_listen() {
  local value=$1 host port
  if [[ "$value" == \[*\]:* ]]; then
    host=${value%%\]*}; host=${host#\[}
    port=${value##*:}
    [[ "$host" == *:* && "$host" =~ ^[0-9A-Fa-f:.]+$ ]] || { echo "面板监听地址无效：$value" >&2; return 1; }
  else
    [[ "$value" == *:* ]] || { echo "面板监听地址需要 HOST:PORT：$value" >&2; return 1; }
    host=${value%:*}
    port=${value##*:}
    [[ -z "$host" || "$host" == 0.0.0.0 || "$host" == localhost || "$host" =~ ^[A-Za-z0-9.-]+$ ]] || {
      echo "面板监听主机无效：$host" >&2
      return 1
    }
  fi
  if [[ ! "$port" =~ ^[0-9]+$ ]] || ((port < 1 || port > 65535)); then
    echo "面板监听端口无效：$port" >&2
    return 1
  fi
}

primary_address() {
  local address=''
  address=$(panel_public_ipv4 || true)
  [[ -n "$address" ]] && { printf '%s\n' "$address"; return 0; }
  if command -v ip >/dev/null 2>&1; then
    address=$(ip route get 1.1.1.1 2>/dev/null | awk '{for (i=1; i<=NF; i++) if ($i == "src") {print $(i+1); exit}}')
  fi
  if [[ -z "$address" ]] && command -v hostname >/dev/null 2>&1; then
    address=$(hostname -I 2>/dev/null | awk '{print $1}')
  fi
  printf '%s\n' "${address:-服务器公网 IP}"
}

print_install_summary() {
  local listen_value scheme host port display_host config_tls
  listen_value="$PANEL_LISTEN"
  if command -v jq >/dev/null 2>&1 && [[ -s "$ETC_DIR/config.json" ]]; then
    listen_value=$(jq -r '.listen // empty' "$ETC_DIR/config.json" 2>/dev/null || true)
    [[ -n "$listen_value" ]] || listen_value="$PANEL_LISTEN"
    config_tls=$(jq -r '.tls.enabled // false' "$ETC_DIR/config.json" 2>/dev/null || printf 'false')
  else
    config_tls=$panel_tls_enabled
  fi
  scheme=http
  [[ "$config_tls" == true || "$panel_tls_enabled" == 1 ]] && scheme=https
  if [[ "$listen_value" == \[*\]*:* ]]; then
    host=${listen_value%%\]*}; host=${host#\[}
    port=${listen_value##*:}
  else
    host=${listen_value%:*}
    port=${listen_value##*:}
  fi
  [[ -n "$port" && "$port" != "$listen_value" ]] || port=9091
  if [[ -z "$host" || "$host" == 0.0.0.0 || "$host" == :: ]]; then
    if [[ "$scheme" == https && -n "$PANEL_TLS_DOMAIN" ]]; then
      display_host="$PANEL_TLS_DOMAIN"
    else
      display_host=$(primary_address)
    fi
  else
    display_host="$host"
  fi
  if [[ "$display_host" == *:* ]]; then display_host="[$display_host]"; fi

  printf '\n================ sb-manager-web 安装完成 ================\n'
  if [[ -n "$initial_credential_output" ]]; then
    printf '%s\n' "$initial_credential_output"
  elif [[ -z "$AGENT_CONTROLLER" ]]; then
    printf '管理员账号已存在，密码不会重复显示。需要重置时运行：sb-web reset-admin-password\n'
  else
    printf '这是 Agent 节点安装，不创建本机面板管理员账号。\n'
  fi
  printf '面板访问地址：%s://%s:%s\n' "$scheme" "$display_host" "$port"
  if [[ "$host" == 127.0.0.1 || "$host" == ::1 || "$host" == localhost ]]; then
    printf '当前仅监听本机；远程访问可建立 SSH 隧道：ssh -N -L %s:127.0.0.1:%s root@服务器公网IP\n' "$port" "$port"
  fi
  if [[ "$scheme" == https && "$PANEL_TLS_MODE" == self-signed ]]; then
    printf '当前使用自签名证书，首次访问时浏览器会显示证书警告。\n'
  fi
  if [[ "$panel_acme_enabled" == 1 ]]; then
    printf '面板 ACME 证书已配置自动续期。\n'
    if [[ "$PANEL_TLS_MODE" == acme-http ]] && panel_is_ip "$PANEL_TLS_DOMAIN"; then
      printf '这是 IP short-lived 证书，续期依赖面板自动续期任务，请勿停用该任务。\n'
    fi
  fi
  if [[ "$host" == 0.0.0.0 || "$host" == :: ]]; then
    printf '请确认云安全组和系统防火墙已放行 TCP %s。\n' "$port"
  fi
  printf '面板服务管理（仅面板）：sb-web enable | sb-web restart | sb-web logs\n'
  printf '底层 sing-box 管理属于独立项目，命令名为 sb；面板不需要用它启动。\n'
}

while (($#)); do
  case "$1" in
    --version) VERSION=${2:?}; shift 2;;
    --no-start) NO_START=1; shift;;
    --panel-tls) PANEL_TLS_MODE=${2:?}; shift 2;;
    --panel-domain) PANEL_TLS_DOMAIN=${2:?}; shift 2;;
    --panel-email) PANEL_TLS_EMAIL=${2:?}; shift 2;;
    --panel-cert) PANEL_TLS_CERT_FILE=${2:?}; shift 2;;
    --panel-key) PANEL_TLS_KEY_FILE=${2:?}; shift 2;;
    --panel-cf-token) PANEL_TLS_CF_TOKEN=${2:?}; shift 2;;
    --panel-cf-zone-id) PANEL_TLS_CF_ZONE_ID=${2:?}; shift 2;;
    --panel-listen) PANEL_LISTEN=${2:?}; panel_listen_override=1; shift 2;;
    --agent) AGENT_CONTROLLER=${2:?}; AGENT_TOKEN=${3:?}; shift 3;;
    --update-only) UPDATE_ONLY=1; shift;;
    -h|--help) usage; exit 0;;
    *) echo "未知参数：$1" >&2; usage; exit 2;;
  esac
done

[[ ${EUID:-$(id -u)} -eq 0 ]] || { echo '请使用 root/sudo 运行。' >&2; exit 1; }
command -v curl >/dev/null 2>&1 || { echo '缺少 curl。' >&2; exit 1; }
panel_validate_listen "$PANEL_LISTEN"
if [[ "$UPDATE_ONLY" == 0 ]] && ! command -v sb >/dev/null 2>&1; then
  if [[ ${SBM_WEB_AUTO_INSTALL_SB:-1} == 1 ]]; then
    install_sb_manager
  else
    echo '未发现 sb-manager，且 SBM_WEB_AUTO_INSTALL_SB=0 禁止了自动安装。' >&2
    exit 1
  fi
fi
command -v sha256sum >/dev/null 2>&1 || { echo '缺少 sha256sum。' >&2; exit 1; }
sb_path=$(command -v sb || true)
init_system=$(detect_init_system)

arch=$(uname -m)
case "$arch" in
  x86_64|amd64) asset_arch=amd64;;
  aarch64|arm64) asset_arch=arm64;;
  armv7l|armv7|armhf) asset_arch=armv7;;
  *) echo "暂不支持的架构：$arch" >&2; exit 1;;
esac

if [[ "$VERSION" == latest ]]; then
  command -v jq >/dev/null 2>&1 || { echo '解析 latest 需要 jq。' >&2; exit 1; }
  VERSION=$(curl --fail --silent --show-error --location "https://api.github.com/repos/$REPO/releases/latest" | jq -r '.tag_name // empty' | sed 's/^v//')
  [[ -n "$VERSION" ]] || { echo '无法解析 sb-manager-web 最新版本。' >&2; exit 1; }
fi

binary_url=${SBM_WEB_BINARY_URL:-"https://github.com/$REPO/releases/download/v$VERSION/sb-web-linux-$asset_arch"}
checksum_url=${SBM_WEB_CHECKSUM_URL:-"https://github.com/$REPO/releases/download/v$VERSION/SHA256SUMS"}
tmp=$(mktemp -d)
install_changed=0
previous_binary="$tmp/previous-sb-web"
rollback_install() {
  if [[ "$install_changed" == 1 && -f "$previous_binary" && -d "$LIB_DIR" ]]; then
    install -m 0755 "$previous_binary" "$LIB_DIR/.sb-web.rollback" 2>/dev/null || return 0
    mv -f "$LIB_DIR/.sb-web.rollback" "$LIB_DIR/sb-web" 2>/dev/null || true
    if [[ -d /run/systemd/system ]] && command -v systemctl >/dev/null 2>&1; then
      systemctl daemon-reload >/dev/null 2>&1 || true
      systemctl restart sb-manager-web.service >/dev/null 2>&1 || true
    fi
  fi
}
trap 'rollback_install; rm -rf "$tmp"' EXIT
if [[ -f "$binary_url" ]]; then
  cp -p "$binary_url" "$tmp/sb-web"
else
  curl --fail --silent --show-error --location "$binary_url" -o "$tmp/sb-web"
fi
chmod 0755 "$tmp/sb-web"
if [[ ${SBM_WEB_SKIP_VERIFY:-0} != 1 ]]; then
  if [[ -f "$checksum_url" ]]; then
    cp -p "$checksum_url" "$tmp/SHA256SUMS"
  else
    curl --fail --silent --show-error --location "$checksum_url" -o "$tmp/SHA256SUMS"
  fi
  expected=$(awk -v file="sb-web-linux-$asset_arch" '$2==file || $2=="*"file {print $1; exit}' "$tmp/SHA256SUMS")
  actual=$(sha256sum "$tmp/sb-web" | awk '{print $1}')
  [[ -n "$expected" && "$expected" == "$actual" ]] || { echo 'sb-web SHA256 校验失败。' >&2; exit 1; }
fi

mkdir -p "$LIB_DIR" "$BIN_DIR" "$ETC_DIR" "$VAR_DIR" "$LOG_DIR"
chmod 0755 "$PREFIX" "$(dirname "$LIB_DIR")" "$LIB_DIR" "$BIN_DIR"
if [[ "$SERVICE_USER" != root ]] && ! id "$SERVICE_USER" >/dev/null 2>&1; then
  if command -v groupadd >/dev/null 2>&1; then groupadd --system "$SERVICE_USER" 2>/dev/null || true
  elif command -v addgroup >/dev/null 2>&1; then addgroup -S "$SERVICE_USER" 2>/dev/null || true; fi
  nologin=$(command -v nologin || true); nologin=${nologin:-/sbin/nologin}
  if command -v useradd >/dev/null 2>&1; then useradd --system --gid "$SERVICE_USER" --home-dir "$VAR_DIR" --shell "$nologin" "$SERVICE_USER"
  elif command -v adduser >/dev/null 2>&1; then adduser -S -D -H -h "$VAR_DIR" -s "$nologin" -G "$SERVICE_USER" "$SERVICE_USER"; fi
fi
if [[ -f "$LIB_DIR/sb-web" ]]; then
  cp -p "$LIB_DIR/sb-web" "$previous_binary"
elif [[ "$UPDATE_ONLY" == 1 ]]; then
  echo "未找到现有 WebUI 二进制：$LIB_DIR/sb-web；更新已取消。" >&2
  exit 1
fi
install -m 0755 "$tmp/sb-web" "$LIB_DIR/.sb-web.new"
mv -f "$LIB_DIR/.sb-web.new" "$LIB_DIR/sb-web"
chown root:root "$LIB_DIR" "$LIB_DIR/sb-web" 2>/dev/null || true
chmod 0755 "$LIB_DIR" "$LIB_DIR/sb-web"
install_changed=1
ln -sfn "$LIB_DIR/sb-web" "$BIN_DIR/sb-web"
if [[ "$UPDATE_ONLY" == 1 ]]; then
  if [[ "$NO_START" == 0 ]]; then
    if [[ "$init_system" == systemd ]] && command -v systemctl >/dev/null 2>&1; then
      systemctl daemon-reload
      for unit in sb-manager-web.service sb-manager-web-agent.service sb-manager-web-helper.service; do
        [[ -f "$SYSTEMD_DIR/$unit" ]] || continue
        [[ "${SBM_WEB_SKIP_HELPER_RESTART:-0}" == 1 && "$unit" == sb-manager-web-helper.service ]] && continue
        if systemctl is-active --quiet "$unit"; then
          systemctl restart "$unit"
        fi
      done
    elif [[ "$init_system" == openrc ]] && command -v rc-service >/dev/null 2>&1; then
      for service in sb-manager-web sb-manager-web-agent sb-manager-web-helper; do
        [[ -f "$OPENRC_DIR/$service" ]] || continue
        [[ "${SBM_WEB_SKIP_HELPER_RESTART:-0}" == 1 && "$service" == sb-manager-web-helper ]] && continue
        if rc-service "$service" status >/dev/null 2>&1; then
          rc-service "$service" restart
        fi
      done
    fi
  fi
  install_changed=0
  echo "sb-manager-web $VERSION 更新完成。"
  exit 0
fi
if [[ ! -e "$ETC_DIR/config.json" ]]; then
  install -m 0600 /dev/stdin "$ETC_DIR/config.json" <<EOF_CONFIG
{
  "listen": "$PANEL_LISTEN",
  "sb_path": "$sb_path",
  "state_file": "/etc/sb-manager/state.json",
  "data_dir": "$VAR_DIR",
  "database": "$VAR_DIR/web.db",
  "log_dir": "$LOG_DIR",
  "backup_dir": "$VAR_DIR/backups",
  "helper_socket": "/run/sb-manager-web/helper.sock",
  "tls": {"enabled": false, "cert_file": "", "key_file": "", "client_ca_file": "", "client_ca_key_file": "", "require_agent_mtls": false},
  "agent": {"enabled": false, "controller_url": "", "identity_file": "$VAR_DIR/agent-identity/ed25519.json", "heartbeat_interval": "30s"},
  "tasks": {"default_timeout": "10m", "batch_concurrency": 1, "failure_stop_percent": 25}
}
EOF_CONFIG
fi
if [[ -z "$AGENT_CONTROLLER" ]]; then
  if initial_credential_output=$("$BIN_DIR/sb-web" init --config "$ETC_DIR/config.json" 2>&1); then
    :
  else
    init_rc=$?
    printf '%s\n' "$initial_credential_output" >&2
    exit "$init_rc"
  fi
fi
panel_tls_setup
[[ -f "$PANEL_ACME_HOME/panel-certificate" ]] && panel_acme_enabled=1
chown -R "$SERVICE_USER:$SERVICE_USER" "$ETC_DIR" "$VAR_DIR" "$LOG_DIR" 2>/dev/null || true
chmod 0750 "$ETC_DIR" "$VAR_DIR" "$LOG_DIR"
if [[ "$panel_acme_enabled" == 1 ]]; then
  chown -R root:root "$PANEL_ACME_HOME" 2>/dev/null || true
  chmod 0700 "$PANEL_ACME_HOME"
fi
if ! service_user_can_execute_web; then
  echo "$SERVICE_USER 无法执行 $BIN_DIR/sb-web；已取消启动服务。" >&2
  if command -v namei >/dev/null 2>&1; then namei -l "$BIN_DIR/sb-web" >&2 || true; fi
  exit 1
fi
if [[ "$init_system" == systemd ]]; then
  mkdir -p "$SYSTEMD_DIR"
  cleanup_legacy_openrc_services
  install -m 0644 /dev/stdin "$SYSTEMD_DIR/sb-manager-web.service" <<EOF_SYSTEMD
[Unit]
Description=sb-manager Go WebUI
After=network-online.target sb-manager-web-helper.service
Wants=network-online.target
Requires=sb-manager-web-helper.service

[Service]
Type=simple
ExecStart=$BIN_DIR/sb-web server --config $ETC_DIR/config.json
Restart=on-failure
RestartSec=3s
User=$SERVICE_USER
Group=$SERVICE_USER
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=full
ReadWritePaths=$VAR_DIR $LOG_DIR /run/sb-manager-web

[Install]
WantedBy=multi-user.target
EOF_SYSTEMD
  install -m 0644 /dev/stdin "$SYSTEMD_DIR/sb-manager-web-helper.service" <<EOF_HELPER_SYSTEMD
[Unit]
Description=sb-manager WebUI privileged helper
After=network.target

[Service]
Type=simple
ExecStart=$BIN_DIR/sb-web helper --config $ETC_DIR/config.json
Restart=on-failure
RestartSec=3s
User=root
Group=$SERVICE_USER
UMask=0007
RuntimeDirectory=sb-manager-web
RuntimeDirectoryMode=0750
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=full
ReadWritePaths=/etc/sb-manager /etc/sysctl.d /var/lib/sb-manager /var/log/sb-manager /run/sb-manager /run/sb-manager-web $LIB_DIR /usr/local/lib/sb-manager $BIN_DIR /usr/local/bin

[Install]
WantedBy=multi-user.target
EOF_HELPER_SYSTEMD
  install -m 0644 /dev/stdin "$SYSTEMD_DIR/sb-manager-web-agent.service" <<EOF_AGENT_SYSTEMD
[Unit]
Description=sb-manager WebUI remote Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=$BIN_DIR/sb-web agent --config $ETC_DIR/config.json
Restart=always
RestartSec=5s
User=root
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=full
ReadWritePaths=$ETC_DIR /etc/sb-manager /etc/sysctl.d $VAR_DIR /var/lib/sb-manager $LOG_DIR /var/log/sb-manager /run/sb-manager-web /run/sb-manager $LIB_DIR /usr/local/lib/sb-manager $BIN_DIR /usr/local/bin

[Install]
WantedBy=multi-user.target
EOF_AGENT_SYSTEMD
  if [[ "$panel_acme_enabled" == 1 ]]; then
    install -m 0644 /dev/stdin "$SYSTEMD_DIR/sb-manager-web-cert-renew.service" <<EOF_CERT_RENEW_SYSTEMD
[Unit]
Description=sb-manager WebUI panel certificate renewal
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=$PANEL_ACME_HOME/acme.sh --home $PANEL_ACME_HOME --config-home $PANEL_ACME_HOME/config --cert-home $PANEL_ACME_HOME/certs --cron
EOF_CERT_RENEW_SYSTEMD
    install -m 0644 /dev/stdin "$SYSTEMD_DIR/sb-manager-web-cert-renew.timer" <<EOF_CERT_RENEW_TIMER_SYSTEMD
[Unit]
Description=Periodic sb-manager WebUI panel certificate renewal

[Timer]
OnBootSec=30min
OnUnitActiveSec=12h
RandomizedDelaySec=1h
Persistent=true

[Install]
WantedBy=timers.target
EOF_CERT_RENEW_TIMER_SYSTEMD
  fi
fi
if [[ "$init_system" == openrc ]]; then
  mkdir -p "$OPENRC_DIR"
  install -m 0755 /dev/stdin "$OPENRC_DIR/sb-manager-web" <<EOF_OPENRC
#!/sbin/openrc-run
name="sb-manager-web"
description="sb-manager Go WebUI"
command="$BIN_DIR/sb-web"
command_args="server --config $ETC_DIR/config.json"
command_user="$SERVICE_USER:$SERVICE_USER"
supervisor="supervise-daemon"
supervise_daemon_args="--stdout $LOG_DIR/server.log --stderr $LOG_DIR/server.err.log"
output_log="$LOG_DIR/server.log"
error_log="$LOG_DIR/server.err.log"
pidfile="/run/\${RC_SVCNAME}.pid"
command_background="yes"
respawn_delay=3
depend() { need net sb-manager-web-helper; after firewall; }
EOF_OPENRC
  install -m 0755 /dev/stdin "$OPENRC_DIR/sb-manager-web-helper" <<EOF_HELPER_OPENRC
#!/sbin/openrc-run
name="sb-manager-web-helper"
description="sb-manager WebUI privileged helper"
command="$BIN_DIR/sb-web"
command_args="helper --config $ETC_DIR/config.json"
command_user="root:$SERVICE_USER"
supervisor="supervise-daemon"
pidfile="/run/\${RC_SVCNAME}.pid"
command_background="yes"
respawn_delay=3
start_pre() { checkpath -d -m 0750 -o root:$SERVICE_USER /run/sb-manager-web; }
EOF_HELPER_OPENRC
  install -m 0755 /dev/stdin "$OPENRC_DIR/sb-manager-web-agent" <<EOF_AGENT_OPENRC
#!/sbin/openrc-run
name="sb-manager-web-agent"
description="sb-manager WebUI remote Agent"
command="$BIN_DIR/sb-web"
command_args="agent --config $ETC_DIR/config.json"
command_user="root:root"
supervisor="supervise-daemon"
supervise_daemon_args="--stdout /var/log/sb-manager-web/agent.log --stderr /var/log/sb-manager-web/agent.err.log"
output_log="/var/log/sb-manager-web/agent.log"
error_log="/var/log/sb-manager-web/agent.err.log"
pidfile="/run/\${RC_SVCNAME}.pid"
command_background="yes"
respawn_delay=5
depend() { need net; }
EOF_AGENT_OPENRC
  if [[ "$panel_acme_enabled" == 1 ]]; then
    mkdir -p "$PERIODIC_DIR/daily"
    install -m 0755 /dev/stdin "$PERIODIC_DIR/daily/sb-manager-web-cert-renew" <<EOF_CERT_RENEW_OPENRC
#!/bin/sh
exec $PANEL_ACME_HOME/acme.sh --home $PANEL_ACME_HOME --config-home $PANEL_ACME_HOME/config --cert-home $PANEL_ACME_HOME/certs --cron >/dev/null 2>&1
EOF_CERT_RENEW_OPENRC
  fi
fi
if [[ "$NO_START" == 0 ]]; then
  if [[ -n "$AGENT_CONTROLLER" ]]; then
    "$BIN_DIR/sb-web" join "$AGENT_CONTROLLER" "$AGENT_TOKEN" --config "$ETC_DIR/config.json"
  elif [[ "$init_system" == systemd ]] && command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload
    systemd_units=(sb-manager-web-helper.service sb-manager-web.service)
    [[ "$panel_acme_enabled" == 1 ]] && systemd_units+=(sb-manager-web-cert-renew.timer)
    systemctl enable --now "${systemd_units[@]}"
    systemctl restart sb-manager-web-helper.service sb-manager-web.service
  elif [[ "$init_system" == openrc ]] && command -v rc-update >/dev/null 2>&1 && command -v rc-service >/dev/null 2>&1; then
    rc-update add sb-manager-web-helper default || true
    rc-update add sb-manager-web default || true
    rc-service sb-manager-web-helper restart || rc-service sb-manager-web-helper start
    rc-service sb-manager-web restart || rc-service sb-manager-web start
  else
    echo '未发现正在运行的 systemd/OpenRC；请手动运行 sb-web server。' >&2
  fi
fi
install_changed=0
echo "sb-manager-web $VERSION 安装完成。"
print_install_summary
