# shellcheck shell=bash
# Wypisuje (NUL-separated) ścieżki katalogów lib/ konsumentów PFrame pod DEV_DIR,
# także w aplikacjach zagnieżdżonych w monorepozytoriach. Pomija samo repozytorium pframe.
pframe_consumer_lib_dirs() {
    local dev_dir="$1" repo_dir relative_path
    local repo_dirs=()
    if [[ -e "$dev_dir/.git" ]]; then
        repo_dirs+=("$dev_dir")
    else
        for repo_dir in "$dev_dir"/*; do
            [[ -e "$repo_dir/.git" ]] || continue
            repo_dirs+=("$repo_dir")
        done
    fi

    for repo_dir in "${repo_dirs[@]}"; do
        while IFS= read -r -d '' relative_path; do
            local lib_dir name
            lib_dir="$(dirname "$repo_dir/$relative_path")"
            name="$(pframe_consumer_name "$dev_dir" "$lib_dir")"
            [[ "${name%%/*}" == pframe ]] && continue
            printf '%s\0' "$lib_dir"
        done < <(git -C "$repo_dir" ls-files -z -- ':(glob)**/lib/PFrame.php')
    done
}

# Nazwa konsumenta: ścieżka względem DEV_DIR bez końcowego /lib i /app/lib.
pframe_consumer_name() {
    local name="${2#"$1"/}"
    name="${name%/lib}"
    printf '%s' "${name%/app}"
}
