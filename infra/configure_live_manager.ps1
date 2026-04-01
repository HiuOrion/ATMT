$container = "atmt-wazuh-manager-live"
$ruleSource = Join-Path $PSScriptRoot "wazuh\\custom_rules\\public_lockbit_rules.xml"
$ruleTarget = "/var/ossec/etc/rules/public_lockbit_rules.xml"
$snippet = @'
<ossec_config>
  <localfile>
    <log_format>json</log_format>
    <location>/var/ossec/logs/replay/live_demo.jsonl</location>
  </localfile>
</ossec_config>
'@

$rulePresent = docker exec $container sh -lc "test -f $ruleTarget && echo PRESENT || echo MISSING"
if ($rulePresent -match "MISSING") {
  docker cp $ruleSource "${container}:$ruleTarget" | Out-Null
}

docker exec $container sh -lc "mkdir -p /var/ossec/logs/alerts /var/ossec/logs/archives /var/ossec/logs/firewall && chown -R wazuh:wazuh /var/ossec/logs"
docker exec $container sh -lc "mkdir -p /var/ossec/logs/replay && : > /var/ossec/logs/replay/live_demo.jsonl && chown wazuh:wazuh /var/ossec/logs/replay/live_demo.jsonl"

$existing = docker exec $container sh -lc "grep -F '/var/ossec/logs/replay/live_demo.jsonl' /var/ossec/etc/ossec.conf >/dev/null && echo PRESENT || echo MISSING"

if ($existing -match "MISSING") {
  $encoded = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($snippet))
  docker exec $container sh -lc "echo $encoded | base64 -d >> /var/ossec/etc/ossec.conf"
}

docker restart $container | Out-Null
Write-Output "Live manager configured."
