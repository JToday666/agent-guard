#!/usr/bin/env bash
set -euo pipefail

repo_root="$(git rev-parse --show-toplevel)"
cd "$repo_root"

mapfile -d '' changed_files < <(
  {
    git diff --name-only -z --diff-filter=ACMR HEAD -- apps/dashboard
    git ls-files --others --exclude-standard -z -- apps/dashboard
  }
)

declare -A seen_files=()
prettier_files=()
eslint_files=()
scss_files=()

for file in "${changed_files[@]}"; do
  [[ -n "$file" ]] || continue
  [[ -z "${seen_files[$file]+x}" ]] || continue
  seen_files["$file"]=1

  case "$file" in
    *.vue|*.ts|*.scss)
      prettier_files+=("${file#apps/dashboard/}")
      ;;
  esac
  case "$file" in
    *.scss)
      scss_files+=("${file#apps/dashboard/}")
      ;;
  esac
  case "$file" in
    *.vue|*.ts)
      eslint_files+=("${file#apps/dashboard/}")
      ;;
  esac
done

if ((${#prettier_files[@]} == 0 && ${#eslint_files[@]} == 0)); then
  echo "No changed dashboard Vue, TypeScript, or SCSS files."
  exit 0
fi

cd "$repo_root/apps/dashboard"

if ((${#eslint_files[@]} > 0)); then
  pnpm exec eslint --fix "${eslint_files[@]}"
fi

if ((${#prettier_files[@]} > 0)); then
  pnpm exec prettier --write "${prettier_files[@]}"
fi

if ((${#scss_files[@]} > 0)); then
  pnpm run build
elif ((${#eslint_files[@]} > 0)); then
  pnpm run typecheck
fi
