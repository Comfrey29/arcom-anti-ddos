rule PHISHING_TEMPLATES {
  meta:
    author = "ArCom"
    description = "Detect common phishing HTML templates strings"
  strings:
    $s1 = "<form method=\"POST\" action=\"/login\""
    $s2 = "name=\"password\""
    $s3 = "paypal" nocase
  condition:
    (any of ($s*)) and filesize < 200KB
}

rule STEALTHLOGGER_INDICATORS {
  meta:
    description = "PHP logger patterns (sensitive)"
  strings:
    $php1 = "file_put_contents" nocase
    $php2 = "mail(" nocase
    $php3 = "base64_decode(" nocase
    $susp = /preg_replace\s*\(\s*["'].*\/e.*["']/
  condition:
    ( $php1 and $php3 ) or $susp
}
