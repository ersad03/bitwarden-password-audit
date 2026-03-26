#!/usr/bin/env bash
set -euo pipefail

SCRIPT_NAME="$(basename "$0")"
VERSION="3.0.0"
umask 077

# Non-printing field separator used in temp data files.
SEP=$'\037'

INPUT_FILE=""
MIN_REPETITION=2
WEAKNESS_SENSITIVITY="medium"
MASK_MODE="quarter"
PREVIEW_RATIO="0.25"
MAX_FINDINGS=10
LIST_ITEMS_FOR=""

KEY_COL_WIDTH=30
ITEMS_COL_WIDTH=58
ITEM_NAMES_PREVIEW_MAX=3

WEAK_THRESHOLD=45

TMP_DIR=""
ENTRIES_FILE=""
PASSWORDS_FILE=""
SCORES_FILE=""
COUNTS_FILE=""
REUSED_FILE=""
WEAK_FILE=""
PRIORITY_FILE=""
STATS_FILE=""

TOTAL_ITEMS=0
UNIQUE_PASSWORDS=0
SKIPPED_EMPTY_PASSWORD_ROWS=0
TOTAL_REUSED_GROUPS=0
TOTAL_WEAK_PASSWORDS=0
TOTAL_WEAK_ENTRIES=0
TOTAL_ACTION_ITEMS=0

# In-memory lookup maps for rendering.
declare -A PW_RAW
declare -A PW_LEN
declare -A PW_SCORE
declare -A PW_SEVERITY
declare -A PW_WEAK
declare -A PW_REASONS
declare -A PW_COUNT
declare -A ENTRY_GROUPS

usage() {
  cat <<'EOF'
Bitwarden Password Health Report (CLI)

Usage:
  bitwarden_password_audit.sh --input /path/to/bitwarden.csv [options]

Required:
  -i, --input FILE                 Bitwarden CSV export file

Options:
  -r, --min-repetition N           Minimum count to mark reuse (default: 2)
  -s, --weakness-sensitivity MODE  low | medium | high (default: medium)
  -m, --mask-mode MODE             hidden | quarter | full (default: quarter)
      --preview-ratio R            Visible character ratio for quarter/full preview mode (default: 0.25)
      --max-findings [N]           Max rows in Priority Issues (default: 10)
      --list-items-for ID          List item names for one password ID (e.g., P003) and exit
  -h, --help                       Show help

Examples:
  ./bitwarden_password_audit.sh --input bitwarden.csv
  ./bitwarden_password_audit.sh --input=bitwarden.csv --max-findings=15
  ./bitwarden_password_audit.sh --input bitwarden.csv --max-findings
  ./bitwarden_password_audit.sh --input bitwarden.csv -m hidden
  ./bitwarden_password_audit.sh --input bitwarden.csv --list-items-for P003

Notes:
  If --max-findings is provided without a value, all findings are shown.
  --max-findings=0 also means show all findings.
  Options accept both '--opt value' and '--opt=value' forms.

Mask modes:
  hidden   Prints fixed mask only (no password length leakage).
  quarter  Reveals a small partial preview (25% by default) plus length.
  full     Prints full password (unsafe; local trusted sessions only).
EOF
}

die() {
  printf 'Error: %s\n' "$1" >&2
  exit 1
}

cleanup() {
  if [[ -n "$TMP_DIR" && -d "$TMP_DIR" ]]; then
    rm -rf "$TMP_DIR"
  fi
}

require_bash4() {
  if (( BASH_VERSINFO[0] < 4 )); then
    die "This script requires Bash 4+ (associative arrays are used)."
  fi
}

require_tools() {
  local missing=0
  local cmd
  for cmd in awk sed grep sort uniq cut wc tr mktemp; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
      printf 'Missing required command: %s\n' "$cmd" >&2
      missing=1
    fi
  done
  (( missing == 0 )) || exit 1
}

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      -i=*|--input=*)
        INPUT_FILE="${1#*=}"
        shift
        ;;
      -i|--input)
        [[ $# -ge 2 && "$2" != -* ]] || die "--input requires a file path"
        INPUT_FILE="$2"
        shift 2
        ;;
      -r=*|--min-repetition=*)
        MIN_REPETITION="${1#*=}"
        shift
        ;;
      -r|--min-repetition)
        [[ $# -ge 2 && "$2" != -* ]] || die "--min-repetition requires a number"
        MIN_REPETITION="$2"
        shift 2
        ;;
      -s=*|--weakness-sensitivity=*)
        WEAKNESS_SENSITIVITY="${1#*=}"
        shift
        ;;
      -s|--weakness-sensitivity)
        [[ $# -ge 2 && "$2" != -* ]] || die "--weakness-sensitivity requires low, medium, or high"
        WEAKNESS_SENSITIVITY="$2"
        shift 2
        ;;
      -m=*|--mask-mode=*)
        MASK_MODE="${1#*=}"
        shift
        ;;
      -m|--mask-mode)
        [[ $# -ge 2 && "$2" != -* ]] || die "--mask-mode requires hidden, quarter, or full"
        MASK_MODE="$2"
        shift 2
        ;;
      --preview-ratio=*)
        PREVIEW_RATIO="${1#*=}"
        shift
        ;;
      --preview-ratio)
        [[ $# -ge 2 && "$2" != -* ]] || die "--preview-ratio requires a decimal value"
        PREVIEW_RATIO="$2"
        shift 2
        ;;
      --max-findings=*)
        MAX_FINDINGS="${1#*=}"
        shift
        ;;
      --max-findings)
        # If value is omitted, show all.
        if [[ $# -ge 2 && "$2" != -* ]]; then
          MAX_FINDINGS="$2"
          shift 2
        else
          MAX_FINDINGS=0
          shift
        fi
        ;;
      --list-items-for=*)
        LIST_ITEMS_FOR="${1#*=}"
        shift
        ;;
      --list-items-for)
        [[ $# -ge 2 && "$2" != -* ]] || die "--list-items-for requires a password ID like P003"
        LIST_ITEMS_FOR="$2"
        shift 2
        ;;
      -h|--help)
        usage
        exit 0
        ;;
      *)
        die "Unknown argument: $1"
        ;;
    esac
  done
}

validate_args() {
  [[ -n "$INPUT_FILE" ]] || die "Input is required. Use --input FILE"
  [[ -f "$INPUT_FILE" ]] || die "Input file not found: $INPUT_FILE"
  [[ -r "$INPUT_FILE" ]] || die "Input file is not readable: $INPUT_FILE"
  [[ -s "$INPUT_FILE" ]] || die "Input file is empty: $INPUT_FILE"

  [[ "$MIN_REPETITION" =~ ^[0-9]+$ ]] || die "--min-repetition must be an integer >= 2"
  (( MIN_REPETITION >= 2 )) || die "--min-repetition must be an integer >= 2"

  [[ "$MAX_FINDINGS" =~ ^[0-9]+$ ]] || die "--max-findings must be an integer >= 0"
  (( MAX_FINDINGS >= 0 )) || die "--max-findings must be an integer >= 0"

  case "$WEAKNESS_SENSITIVITY" in
    low) WEAK_THRESHOLD=60 ;;
    medium) WEAK_THRESHOLD=45 ;;
    high) WEAK_THRESHOLD=30 ;;
    *) die "--weakness-sensitivity must be low, medium, or high" ;;
  esac

  case "$MASK_MODE" in
    hidden|quarter|full) ;;
    *) die "--mask-mode must be hidden, quarter, or full" ;;
  esac

  # Accept preview ratio in [0.05, 0.50]
  awk -v r="$PREVIEW_RATIO" 'BEGIN { exit !(r ~ /^[0-9]*\.?[0-9]+$/ && r >= 0.05 && r <= 0.50) }' \
    || die "--preview-ratio must be between 0.05 and 0.50"

  if [[ -n "$LIST_ITEMS_FOR" ]]; then
    [[ "$LIST_ITEMS_FOR" =~ ^[Pp]?[0-9]+$ ]] || die "--list-items-for must be like P003 or 3"
  fi
}

init_workspace() {
  TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/bw-pass-audit.XXXXXX")"

  ENTRIES_FILE="$TMP_DIR/entries.dat"
  PASSWORDS_FILE="$TMP_DIR/passwords.dat"
  SCORES_FILE="$TMP_DIR/scores.dat"
  COUNTS_FILE="$TMP_DIR/counts.dat"
  REUSED_FILE="$TMP_DIR/reused.dat"
  WEAK_FILE="$TMP_DIR/weak.dat"
  PRIORITY_FILE="$TMP_DIR/priority.dat"
  STATS_FILE="$TMP_DIR/stats.env"

  : > "$ENTRIES_FILE"
  : > "$PASSWORDS_FILE"
  : > "$SCORES_FILE"
  : > "$COUNTS_FILE"
  : > "$REUSED_FILE"
  : > "$WEAK_FILE"
  : > "$PRIORITY_FILE"
  : > "$STATS_FILE"
}

parse_and_normalize_csv() {
  awk -v sep="$SEP" \
      -v entries_file="$ENTRIES_FILE" \
      -v passwords_file="$PASSWORDS_FILE" \
      -v stats_file="$STATS_FILE" '
    function trim(s) {
      sub(/^[[:space:]]+/, "", s)
      sub(/[[:space:]]+$/, "", s)
      return s
    }

    function normalize_label(s, t) {
      t = tolower(trim(s))
      gsub(/[[:space:]]+/, "_", t)
      return t
    }

    function normalize_text(s, t) {
      t = s
      gsub(/\r/, "", t)
      gsub(/\n/, " ", t)
      gsub(/\t/, " ", t)
      gsub(sep, " ", t)
      t = trim(t)
      return (t == "" ? "-" : t)
    }

    function extract_domain(uri, u, p, c) {
      u = trim(uri)
      if (u == "") return "-"

      gsub(/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//, "", u)
      sub(/^[^@]*@/, "", u)
      c = split(u, p, /[\/?#]/)
      u = p[1]
      sub(/:[0-9]+$/, "", u)
      u = tolower(trim(u))
      return (u == "" ? "-" : u)
    }

    function parse_csv_record(rec, out, i, ch, nextch, in_q, n, field) {
      delete out
      n = 1
      field = ""
      in_q = 0

      for (i = 1; i <= length(rec); i++) {
        ch = substr(rec, i, 1)
        nextch = substr(rec, i + 1, 1)

        if (in_q) {
          if (ch == "\"") {
            if (nextch == "\"") {
              field = field "\""
              i++
            } else {
              in_q = 0
            }
          } else {
            field = field ch
          }
        } else {
          if (ch == "\"") {
            in_q = 1
          } else if (ch == ",") {
            out[n++] = field
            field = ""
          } else {
            field = field ch
          }
        }
      }

      out[n] = field
      return n
    }

    function emit_record(rec, fields, count, i, key, pidx, nidx, uidx, ridx, pw, name, user, uri, domain, id) {
      if (rec == "") return
      count = parse_csv_record(rec, fields)

      if (!header_ready) {
        for (i = 1; i <= count; i++) {
          key = normalize_label(fields[i])
          idx[key] = i
        }
        if (!("login_password" in idx) || !("name" in idx)) {
          print "ERROR: CSV header missing required Bitwarden columns (name/login_password)." > "/dev/stderr"
          parse_error = 1
        }
        header_ready = 1
        return
      }

      pidx = idx["login_password"]
      pw = (pidx <= count ? fields[pidx] : "")
      if (pw == "") {
        skipped_empty++
        return
      }

      nidx = idx["name"]
      name = normalize_text((nidx <= count ? fields[nidx] : ""))

      if ("login_username" in idx) {
        uidx = idx["login_username"]
        user = normalize_text((uidx <= count ? fields[uidx] : ""))
      } else {
        user = "-"
      }

      if ("login_uri" in idx) {
        ridx = idx["login_uri"]
        uri = (ridx <= count ? fields[ridx] : "")
      } else {
        uri = ""
      }
      domain = extract_domain(uri)

      if (!(pw in pw_id)) {
        pw_id[pw] = ++unique_pw
        print pw_id[pw] sep pw >> passwords_file
      }

      id = pw_id[pw]
      print id sep name sep user sep domain >> entries_file
      total_items++
    }

    BEGIN {
      parse_error = 0
      header_ready = 0
      in_quotes = 0
      rec = ""
      total_items = 0
      unique_pw = 0
      skipped_empty = 0
    }

    {
      line = $0
      sub(/\r$/, "", line)
      text = line "\n"

      for (i = 1; i <= length(text); i++) {
        ch = substr(text, i, 1)
        nextch = substr(text, i + 1, 1)
        rec = rec ch

        if (ch == "\"") {
          if (in_quotes && nextch == "\"") {
            rec = rec nextch
            i++
            continue
          }
          in_quotes = !in_quotes
        }

        if (ch == "\n" && !in_quotes) {
          sub(/\n$/, "", rec)
          emit_record(rec)
          rec = ""
        }
      }
    }

    END {
      if (rec != "") {
        emit_record(rec)
      }

      if (parse_error) exit 2
      if (!header_ready) {
        print "ERROR: CSV appears empty or malformed." > "/dev/stderr"
        exit 2
      }
      if (in_quotes) {
        print "ERROR: CSV appears malformed (unbalanced quotes)." > "/dev/stderr"
        exit 2
      }

      print "TOTAL_ITEMS=" total_items > stats_file
      print "UNIQUE_PASSWORDS=" unique_pw >> stats_file
      print "SKIPPED_EMPTY_PASSWORD_ROWS=" skipped_empty >> stats_file
    }
  ' "$INPUT_FILE"
}

score_passwords() {
  awk -v sep="$SEP" -v threshold="$WEAK_THRESHOLD" '
    function add(points, reason) {
      score += points
      if (reason != "") {
        if (reasons != "") reasons = reasons "; " reason
        else reasons = reason
      }
    }

    function rev(s, i, out) {
      out = ""
      for (i = length(s); i >= 1; i--) out = out substr(s, i, 1)
      return out
    }

    function classes_count(s, n) {
      n = 0
      if (s ~ /[a-z]/) n++
      if (s ~ /[A-Z]/) n++
      if (s ~ /[0-9]/) n++
      if (s ~ /[^[:alnum:]]/) n++
      return n
    }

    function has_triplet(s, i, a, b, c) {
      for (i = 1; i <= length(s) - 2; i++) {
        a = substr(s, i, 1)
        b = substr(s, i + 1, 1)
        c = substr(s, i + 2, 1)
        if (a == b && b == c) return 1
      }
      return 0
    }

    function find_sequence(s, low, seqs, n, i, j, seq, p, r) {
      low = tolower(s)
      n = split("abcdefghijklmnopqrstuvwxyz|0123456789", seqs, "|")
      for (i = 1; i <= n; i++) {
        seq = seqs[i]
        for (j = 1; j <= length(seq) - 3; j++) {
          p = substr(seq, j, 4)
          r = rev(p)
          if (index(low, p) > 0) return p
          if (index(low, r) > 0) return r
        }
      }
      return ""
    }

    function find_keyboard(s, low, seqs, n, i, j, seq, p, r) {
      low = tolower(s)
      n = split("qwertyuiop|asdfghjkl|zxcvbnm|1qaz|2wsx|3edc|zaq1", seqs, "|")
      for (i = 1; i <= n; i++) {
        seq = seqs[i]
        for (j = 1; j <= length(seq) - 3; j++) {
          p = substr(seq, j, 4)
          r = rev(p)
          if (index(low, p) > 0) return p
          if (index(low, r) > 0) return r
        }
      }
      return ""
    }

    function weak_severity(score) {
      if (score >= 85) return "critical"
      if (score >= 70) return "high"
      if (score >= 50) return "medium"
      if (score >= threshold) return "low"
      return "info"
    }

    {
      split_idx = index($0, sep)
      if (split_idx <= 0) next

      id = substr($0, 1, split_idx - 1)
      pw = substr($0, split_idx + 1)

      len = length(pw)
      lower = tolower(pw)
      score = 0
      reasons = ""

      if (len < 8) add(35, "very short")
      else if (len < 10) add(22, "short")
      else if (len < 12) add(10, "borderline length")

      classes = classes_count(pw)
      if (classes == 1) add(30, "single character class")
      else if (classes == 2) add(18, "low character variety")
      else if (classes == 3) add(8, "missing one character class")

      if (pw !~ /[^[:alnum:]]/) add(8, "no symbols")
      if (has_triplet(pw)) add(15, "repeated character runs")

      seq_hit = find_sequence(pw)
      if (seq_hit != "") add(18, "sequence pattern " seq_hit)

      key_hit = find_keyboard(pw)
      if (key_hit != "") add(20, "keyboard pattern " key_hit)

      if (lower ~ /(password|admin|welcome|qwerty|letmein|dragon|monkey|abc123|123456|secret)/) {
        add(25, "common-password trait")
      }

      if (lower ~ /(19|20)[0-9][0-9]$/) add(8, "year suffix")
      if (lower ~ /^[a-z]+[[:punct:]]?[0-9]+$/) add(10, "predictable word+number")

      if (score > 100) score = 100
      weak = (score >= threshold ? 1 : 0)

      print id sep len sep score sep weak_severity(score) sep weak sep reasons
    }
  ' "$PASSWORDS_FILE" > "$SCORES_FILE"
}

aggregate_data() {
  # Counts per password id.
  cut -d "$SEP" -f1 "$ENTRIES_FILE" | sort | uniq -c | awk -v sep="$SEP" '{print $2 sep $1}' > "$COUNTS_FILE"

  awk -F "$SEP" -v min="$MIN_REPETITION" '$2 >= min { print $0 }' "$COUNTS_FILE" | sort -t "$SEP" -k2,2nr > "$REUSED_FILE"
  awk -F "$SEP" '$5 == 1 { print $0 }' "$SCORES_FILE" | sort -t "$SEP" -k3,3nr > "$WEAK_FILE"

  # Priority queue: passwords that are weak and/or reused.
  awk -F "$SEP" -v sep="$SEP" -v min="$MIN_REPETITION" '
    NR == FNR { cnt[$1] = $2; next }
    {
      id = $1
      len = $2
      weak_score = $3
      weak_sev = $4
      weak = $5
      reasons = $6
      reused = ((id in cnt) ? cnt[id] : 1)

      if (weak == 0 && reused < min) next

      impact = weak_score
      if (reused >= min) impact += (reused - 1) * 12
      if (weak == 1 && reused >= min) impact += 15
      if (impact > 100) impact = 100

      if (impact >= 90) sev = "critical"
      else if (impact >= 75) sev = "high"
      else if (impact >= 55) sev = "medium"
      else sev = "low"

      print id sep impact sep sev sep reused sep weak_score sep weak sep reasons
    }
  ' "$COUNTS_FILE" "$SCORES_FILE" | sort -t "$SEP" -k2,2nr -k4,4nr -k5,5nr > "$PRIORITY_FILE"

  # Load global totals.
  while IFS='=' read -r k v; do
    case "$k" in
      TOTAL_ITEMS) TOTAL_ITEMS="$v" ;;
      UNIQUE_PASSWORDS) UNIQUE_PASSWORDS="$v" ;;
      SKIPPED_EMPTY_PASSWORD_ROWS) SKIPPED_EMPTY_PASSWORD_ROWS="$v" ;;
    esac
  done < "$STATS_FILE"

  TOTAL_REUSED_GROUPS="$(wc -l < "$REUSED_FILE" | tr -d ' ')"
  TOTAL_WEAK_PASSWORDS="$(wc -l < "$WEAK_FILE" | tr -d ' ')"
  TOTAL_ACTION_ITEMS="$(wc -l < "$PRIORITY_FILE" | tr -d ' ')"

  if [[ -s "$WEAK_FILE" ]]; then
    TOTAL_WEAK_ENTRIES="$(awk -F "$SEP" 'NR==FNR{w[$1]=1;next} ($1 in w){c++} END{print c+0}' "$WEAK_FILE" "$ENTRIES_FILE")"
  else
    TOTAL_WEAK_ENTRIES=0
  fi
}

load_lookup_maps() {
  local keep_raw=0
  if [[ "$MASK_MODE" == "quarter" || "$MASK_MODE" == "full" ]]; then
    keep_raw=1
  fi

  while IFS="$SEP" read -r id password; do
    [[ -z "$id" ]] && continue
    if (( keep_raw == 1 )); then
      PW_RAW["$id"]="$password"
    fi
  done < "$PASSWORDS_FILE"

  while IFS="$SEP" read -r id len score severity weak reasons; do
    [[ -z "$id" ]] && continue
    PW_LEN["$id"]="$len"
    PW_SCORE["$id"]="$score"
    PW_SEVERITY["$id"]="$severity"
    PW_WEAK["$id"]="$weak"
    PW_REASONS["$id"]="$reasons"
  done < "$SCORES_FILE"

  while IFS="$SEP" read -r id count; do
    [[ -z "$id" ]] && continue
    PW_COUNT["$id"]="$count"
  done < "$COUNTS_FILE"

  while IFS="$SEP" read -r id name user domain; do
    [[ -z "$id" ]] && continue
    if [[ -n "${ENTRY_GROUPS[$id]:-}" ]]; then
      ENTRY_GROUPS["$id"]+=$'\n'
    fi
    ENTRY_GROUPS["$id"]+="$name"$'\t'"$user"$'\t'"$domain"
  done < "$ENTRIES_FILE"
}

sanitize_printable() {
  printf '%s' "$1" | tr -c '[:print:]' '?'
}

password_label() {
  printf 'P%03d' "$1"
}

mask_password_view() {
  local id="$1"
  local max_width="${2:-0}"
  local len="${PW_LEN[$id]:-0}"

  format_with_len() {
    local core="$1"
    local plen="$2"
    local width="$3"
    local suffix=" len=${plen}>"

    if (( width <= 0 )); then
      printf '<%s%s' "$core" "$suffix"
      return
    fi

    local avail=$(( width - 1 - ${#suffix} )) # 1 for leading '<'
    if (( avail < 1 )); then
      printf '<*%s' "$suffix"
      return
    fi

    if (( ${#core} <= avail )); then
      printf '<%s%s' "$core" "$suffix"
      return
    fi

    if (( avail <= 3 )); then
      printf '<%.*s%s' "$avail" "$core" "$suffix"
      return
    fi

    printf '<%s...%s' "${core:0:$(( avail - 3 ))}" "$suffix"
  }

  case "$MASK_MODE" in
    hidden)
      printf '<****>'
      ;;
    quarter)
      local pw="${PW_RAW[$id]:-}"
      if [[ -z "$pw" ]]; then
        printf '<****>'
        return
      fi

      local reveal front back middle
      reveal="$(awk -v l="$len" -v r="$PREVIEW_RATIO" 'BEGIN { v=int(l*r+0.999); if (v<1) v=1; if (v>l) v=l; print v }')"
      front=$(( (reveal + 1) / 2 ))
      back=$(( reveal - front ))
      if (( front + back > len )); then
        back=$(( len - front ))
      fi
      if (( back < 0 )); then
        back=0
      fi
      middle=$(( len - front - back ))

      local first last stars
      first="$(sanitize_printable "${pw:0:front}")"
      if (( back > 0 )); then
        last="$(sanitize_printable "${pw: -back}")"
      else
        last=""
      fi
      if (( middle > 0 )); then
        stars='****'
      else
        stars=''
      fi

      format_with_len "${first}${stars}${last}" "$len" "$max_width"
      ;;
    full)
      format_with_len "$(sanitize_printable "${PW_RAW[$id]:-}")" "$len" "$max_width"
      ;;
  esac
}

trim_reason() {
  local text="$1"
  local max_len="$2"
  if (( ${#text} <= max_len )); then
    printf '%s' "$text"
  else
    printf '%s...' "${text:0:max_len-3}"
  fi
}

fit_cell() {
  local text="$1"
  local width="$2"
  if (( width < 1 )); then
    printf ''
    return
  fi
  if (( ${#text} <= width )); then
    printf '%s' "$text"
    return
  fi
  if (( width <= 3 )); then
    printf '%.*s' "$width" "$text"
    return
  fi
  local cut=$(( width - 3 ))
  printf '%s...' "${text:0:cut}"
}

sample_item_names() {
  local id="$1"
  local max_names="$2"
  local max_width="$3"
  local group="${ENTRY_GROUPS[$id]:-}"

  if [[ -z "$group" ]]; then
    printf '%s' '-'
    return
  fi

  declare -A seen=()
  local unique_names=()
  mapfile -t rows <<< "$group"

  local i
  for (( i = 0; i < ${#rows[@]}; i++ )); do
    local name user domain key
    IFS=$'\t' read -r name user domain <<< "${rows[$i]}"
    key="$name"
    if [[ -n "${seen[$key]:-}" ]]; then
      continue
    fi
    seen["$key"]=1
    unique_names+=("$name")
  done

  local total="${#unique_names[@]}"
  local display_names="$total"
  (( display_names > max_names )) && display_names="$max_names"
  local extra_total=$(( total - display_names ))

  local out="" included=0
  for (( i = 0; i < display_names; i++ )); do
    local item chunk candidate hidden_if_include suffix_if_include
    item="$(trim_reason "${unique_names[$i]}" 26)"
    if [[ -z "$out" ]]; then
      candidate="$item"
    else
      candidate="$out, $item"
    fi

    hidden_if_include=$(( extra_total + (display_names - (i + 1)) ))
    if (( hidden_if_include > 0 )); then
      suffix_if_include=" ... +${hidden_if_include}"
    else
      suffix_if_include=""
    fi

    if (( ${#candidate} + ${#suffix_if_include} <= max_width )); then
      out="$candidate"
      included=$(( i + 1 ))
    else
      break
    fi
  done

  local hidden_total=$(( extra_total + (display_names - included) ))
  if [[ -z "$out" && ${#unique_names[@]} -gt 0 ]]; then
    # Ensure we always show at least one readable name chunk.
    local suffix=""
    if (( hidden_total > 0 )); then
      suffix=" ... +${hidden_total}"
    fi
    local avail=$(( max_width - ${#suffix} ))
    (( avail < 1 )) && avail=1
    out="$(fit_cell "$(trim_reason "${unique_names[0]}" 26)" "$avail")$suffix"
    printf '%s' "$out"
    return
  fi

  if (( hidden_total > 0 )); then
    out+=" ... +${hidden_total}"
  fi

  printf '%s' "$(fit_cell "$out" "$max_width")"
}

normalize_id_arg() {
  local raw="$1"
  local n="$raw"
  n="${n#P}"
  n="${n#p}"
  [[ "$n" =~ ^[0-9]+$ ]] || return 1
  printf '%d' "$((10#$n))"
}

print_item_list_for_id() {
  local raw="$1"
  local id
  id="$(normalize_id_arg "$raw")" || die "Invalid password ID: $raw"

  local group="${ENTRY_GROUPS[$id]:-}"
  if [[ -z "$group" ]]; then
    die "No entries found for password ID $(password_label "$id")"
  fi

  declare -A seen=()
  mapfile -t rows <<< "$group"

  echo "Item Names For $(password_label "$id")"
  divider

  local i count=0
  for (( i = 0; i < ${#rows[@]}; i++ )); do
    local name user domain
    IFS=$'\t' read -r name user domain <<< "${rows[$i]}"
    if [[ -n "${seen[$name]:-}" ]]; then
      continue
    fi
    seen["$name"]=1
    count=$(( count + 1 ))
    printf '  %s. %s\n' "$count" "$name"
  done
  echo
  echo "Total unique item names: $count"
}

divider() {
  printf '%s\n' "----------------------------------------------------------------------------"
}

print_heading() {
  printf '\n%s\n' "$1"
  divider
}

print_snapshot() {
  printf 'Snapshot: items=%s | unique=%s | reused=%s | weak=%s | actions=%s\n' \
    "$TOTAL_ITEMS" "$UNIQUE_PASSWORDS" "$TOTAL_REUSED_GROUPS" "$TOTAL_WEAK_PASSWORDS" "$TOTAL_ACTION_ITEMS"
  printf 'Config  : mask=%s | sensitivity=%s (weak >= %s) | repetition >= %s\n' \
    "$MASK_MODE" "$WEAKNESS_SENSITIVITY" "$WEAK_THRESHOLD" "$MIN_REPETITION"
}

print_action_queue() {
  print_heading "Priority Issues"

  if [[ ! -s "$PRIORITY_FILE" ]]; then
    echo "  No high-risk password patterns detected under current thresholds."
    return
  fi

  printf '  %-6s %-7s %-4s %-6s %-6s %-*s %s\n' \
    "ID" "Type" "Risk" "Reuse" "Weak" "$KEY_COL_WIDTH" "Password Key" "Item Names"
  printf '  %-6s %-7s %-4s %-6s %-6s %-*s %s\n' \
    "--" "----" "----" "-----" "----" "$KEY_COL_WIDTH" "------------" "----------"

  mapfile -t rows < "$PRIORITY_FILE"
  local total="${#rows[@]}"
  local shown="$total"
  if (( MAX_FINDINGS > 0 && shown > MAX_FINDINGS )); then
    shown="$MAX_FINDINGS"
  fi

  local i
  for (( i = 0; i < shown; i++ )); do
    local id impact _severity reuse weak_score weak reasons issue_type
    IFS="$SEP" read -r id impact _severity reuse weak_score weak reasons <<< "${rows[$i]}"
    local weak_display="-"
    if [[ "$weak" == "1" ]]; then
      weak_display="$weak_score"
    fi

    if [[ "$weak" == "1" && "$reuse" -ge "$MIN_REPETITION" ]]; then
      issue_type="both"
    elif [[ "$weak" == "1" ]]; then
      issue_type="weak"
    else
      issue_type="reused"
    fi

    local key_cell names_cell id_label
    id_label="$(password_label "$id")"
    key_cell="$(mask_password_view "$id" "$KEY_COL_WIDTH")"
    names_cell="$(sample_item_names "$id" "$ITEM_NAMES_PREVIEW_MAX" "$ITEMS_COL_WIDTH")"

    printf '  %-6s %-7s %-4s %-6s %-6s %-*s %s\n' \
      "$id_label" \
      "$issue_type" \
      "$impact" \
      "$reuse" \
      "$weak_display" \
      "$KEY_COL_WIDTH" "$key_cell" \
      "$names_cell"
  done

  if (( total > shown )); then
    echo
    echo "  Note: showing top ${shown} of ${total} action items (use --max-findings to change)."
  fi
}

render_report() {
  echo "Bitwarden Password Health Report"
  divider
  print_snapshot
  print_action_queue
}

main() {
  trap cleanup EXIT
  require_bash4
  require_tools
  parse_args "$@"
  validate_args
  init_workspace

  parse_and_normalize_csv
  score_passwords
  aggregate_data
  load_lookup_maps

  if [[ -n "$LIST_ITEMS_FOR" ]]; then
    print_item_list_for_id "$LIST_ITEMS_FOR"
    exit 0
  fi

  render_report
}

main "$@"
