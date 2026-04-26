Set-Location "c:\Users\User1\Documents\GitHub\JobbEBPF"

$files = Get-ChildItem -Recurse -File -Filter *.c |
  Where-Object { $_.Name -notlike '*.bpf.c' } |
  Where-Object { Select-String -Path $_.FullName -Pattern 'int main\(void\)' -Quiet }

foreach ($f in $files) {
  $path = $f.FullName
  $text = Get-Content -Raw -Path $path

  if ($text -notmatch 'common/keep_attached\.h') {
    $incMatches = [regex]::Matches($text, '(?m)^#include\s+.*$')
    if ($incMatches.Count -gt 0) {
      $last = $incMatches[$incMatches.Count - 1]
      $insertPos = $last.Index + $last.Length
      $text = $text.Insert($insertPos, "`r`n#include ""../common/keep_attached.h""")
    }
  }

  $text = [regex]::Replace($text, 'int main\(void\)', 'int main(int argc, char **argv)', 1)

  if ($text -notmatch 'kbpf_scan_keep_attached\(argc, argv\)') {
    $text = [regex]::Replace(
      $text,
      'int main\(int argc, char \*\*argv\)\s*\r?\n\{',
      "int main(int argc, char **argv)`r`n{`r`n    int keep_attached = kbpf_scan_keep_attached(argc, argv);",
      1
    )
  }

  if ($text -notmatch 'kbpf_wait_if_keep_attached\(keep_attached\);') {
    $cleanupRegex = '(?m)^\s*(if\s*\([^\n]*\)\s*)?(bpf_link__destroy|[A-Za-z0-9_]+__destroy|bpf_object__close|close)\s*\('
    $matches = [regex]::Matches($text, $cleanupRegex)
    if ($matches.Count -gt 0) {
      $last = $matches[$matches.Count - 1]
      $lineStart = $text.LastIndexOf("`n", $last.Index)
      if ($lineStart -lt 0) { $lineStart = 0 } else { $lineStart = $lineStart + 1 }
      $insertText = "    kbpf_wait_if_keep_attached(keep_attached);`r`n"
      $text = $text.Insert($lineStart, $insertText)
    }
  }

  Set-Content -Path $path -Value $text -NoNewline
}

Write-Output ("Updated files: {0}" -f $files.Count)
