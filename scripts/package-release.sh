#!/usr/bin/env bash
set -euo pipefail

release_tag=${1:?usage: bash scripts/package-release.sh v0.1.0 [output-dir]}
if [[ ! "$release_tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$ ]]; then
	printf 'invalid release tag: %s\n' "$release_tag" >&2
	exit 2
fi

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
output=${2:-"$root/dist"}
output=$(mkdir -p "$output" && cd "$output" && pwd)
version=${release_tag#v}
stage_root=$(mktemp -d)
trap 'rm -rf "$stage_root"' EXIT

for target in linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64; do
	goos=${target%/*}
	goarch=${target#*/}
	archive="mitnick_${version}_${goos}_${goarch}"
	stage="$stage_root/$archive"
	mkdir -p "$stage"
	binary=mitnick
	if [[ "$goos" == windows ]]; then
		binary=mitnick.exe
	fi

	(
		cd "$root"
		GOOS="$goos" GOARCH="$goarch" CGO_ENABLED=0 go build \
			-trimpath -buildvcs=false \
			-ldflags "-s -w -X github.com/mitnick-security/mitnick/internal/app.Version=$version" \
			-o "$stage/$binary" ./cmd/mitnick
	)
	cp "$root/LICENSE" "$root/README.md" "$root/CHANGELOG.md" "$root/SECURITY.md" \
		"$root/CONTRIBUTING.md" "$root/CODE_OF_CONDUCT.md" "$root/THIRD_PARTY_NOTICES.md" "$stage/"
	cp -R "$root/LICENSES" "$root/docs" "$stage/"
	python3 "$root/scripts/generate-sbom.py" \
		--binary "$stage/$binary" --version "$version" --target "$target" \
		--output "$stage/mitnick.spdx.json"
	(
		cd "$stage_root"
		tar --sort=name --mtime='@0' --owner=0 --group=0 --numeric-owner -cf - "$archive" | gzip -n > "$output/$archive.tar.gz"
	)
done

# Stable asset names let installers use GitHub's /releases/latest/download URL
# without requiring a JSON parser or a GitHub API request on the user's machine.
for target in linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64; do
	goos=${target%/*}
	goarch=${target#*/}
	cp "$output/mitnick_${version}_${goos}_${goarch}.tar.gz" \
		"$output/mitnick_${goos}_${goarch}.tar.gz"
done

(
	cd "$output"
	sha256sum mitnick_*.tar.gz > SHA256SUMS
)
