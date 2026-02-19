#!/usr/bin/env bash
# Rotate claude hook log files in /tmp/.
# Each file is moved to .1.json, .2.json, etc. Existing numbered
# files are bumped up by one before the current file is moved.

set -euo pipefail

LOG_FILES=(
	"/tmp/claude-tool-use.json"
	"/tmp/claude-passthrough.json"
)

#============================================
rotate_one() {
	local src="$1"
	if [ ! -f "$src" ]; then
		echo "skip: $src (not found)"
		return
	fi

	# strip .json to build numbered names like foo.3.json
	local base="${src%.json}"

	# find the highest existing number
	local max=0
	for existing in "${base}".*.json; do
		# skip the glob literal when nothing matches
		[ -f "$existing" ] || continue
		local num="${existing#${base}.}"
		num="${num%.json}"
		if [ "$num" -gt "$max" ] 2>/dev/null; then
			max="$num"
		fi
	done

	# bump existing numbered files from highest down to 1
	local i="$max"
	while [ "$i" -ge 1 ]; do
		mv -v "${base}.${i}.json" "${base}.$(( i + 1 )).json"
		i=$(( i - 1 ))
	done

	# rotate the current file to .1
	mv -v "$src" "${base}.1.json"
}

#============================================
for log in "${LOG_FILES[@]}"; do
	rotate_one "$log"
done

echo "done"
