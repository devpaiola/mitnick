#!/bin/sh
set -eu

REPOSITORY="devpaiola/mitnick"
BASE_URL="https://github.com/${REPOSITORY}/releases/latest/download"
INSTALL_DIR=${MITNICK_INSTALL_DIR:-"${HOME}/.local/bin"}

fail() {
	printf 'mitnick installer: %s\n' "$*" >&2
	exit 1
}

command -v curl >/dev/null 2>&1 || fail "curl é necessário para baixar a release."
command -v tar >/dev/null 2>&1 || fail "tar é necessário para extrair a release."

os=$(uname -s)
case "$os" in
	Linux) goos=linux ;;
	Darwin) goos=darwin ;;
	*) fail "sistema não suportado: ${os}. Use Linux ou macOS." ;;
esac

arch=$(uname -m)
case "$arch" in
	x86_64|amd64) goarch=amd64 ;;
	aarch64|arm64) goarch=arm64 ;;
	*) fail "arquitetura não suportada: ${arch}. Use amd64 ou arm64." ;;
esac

archive="mitnick_${goos}_${goarch}.tar.gz"
tmpdir=$(mktemp -d "${TMPDIR:-/tmp}/mitnick-install.XXXXXX") || fail "não foi possível criar diretório temporário."
trap 'rm -rf "$tmpdir"' EXIT HUP INT TERM

curl --fail --location --silent --show-error "${BASE_URL}/${archive}" -o "${tmpdir}/${archive}" || fail "download falhou; confira se há uma release publicada para ${goos}/${goarch}."
curl --fail --location --silent --show-error "${BASE_URL}/SHA256SUMS" -o "${tmpdir}/SHA256SUMS" || fail "não foi possível baixar SHA256SUMS."

expected=$(awk -v name="$archive" '$2 == name { print $1; exit }' "${tmpdir}/SHA256SUMS")
[ -n "$expected" ] || fail "SHA256SUMS não contém ${archive}."
if command -v sha256sum >/dev/null 2>&1; then
	actual=$(sha256sum "${tmpdir}/${archive}" | awk '{print $1}')
elif command -v shasum >/dev/null 2>&1; then
	actual=$(shasum -a 256 "${tmpdir}/${archive}" | awk '{print $1}')
else
	fail "sha256sum ou shasum é necessário para validar o download."
fi
[ "$actual" = "$expected" ] || fail "checksum inválido para ${archive}."

tar -xzf "${tmpdir}/${archive}" -C "$tmpdir" || fail "não foi possível extrair ${archive}."
binary=
for candidate in "${tmpdir}"/mitnick_*_"${goos}_${goarch}"/mitnick; do
	if [ -f "$candidate" ]; then
		binary=$candidate
		break
	fi
done
[ -n "$binary" ] || fail "o pacote não contém o binário esperado."
mkdir -p "$INSTALL_DIR"
install -m 0755 "$binary" "${INSTALL_DIR}/mitnick" || fail "não foi possível instalar em ${INSTALL_DIR}."

case ":${PATH}:" in
	*":${INSTALL_DIR}:"*) ;;
	*)
		profile="${HOME}/.profile"
		case "${SHELL##*/}" in
			zsh) profile="${HOME}/.zprofile" ;;
			bash) profile="${HOME}/.bashrc" ;;
		esac
		mkdir -p "$(dirname "$profile")"
		if ! grep -Fq '# Mitnick CLI PATH' "$profile" 2>/dev/null; then
			{
				printf '\n# Mitnick CLI PATH\n'
				printf 'export PATH="%s:$PATH"\n' "$INSTALL_DIR"
			} >> "$profile"
		fi
		printf 'PATH configurado em %s. Abra um novo terminal para usar `mitnick`.\n' "$profile"
		;;
esac

printf 'Mitnick instalado em %s/mitnick (%s/%s).\n' "$INSTALL_DIR" "$goos" "$goarch"
if [ "${INSTALL_DIR}" = "${HOME}/.local/bin" ]; then
	"${INSTALL_DIR}/mitnick" version
fi
