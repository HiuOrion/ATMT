$container = "atmt-wazuh-manager-live"
$ruleSource = Join-Path $PSScriptRoot "wazuh\\custom_rules\\public_lockbit_rules.xml"
$ruleTarget = "/var/ossec/etc/rules/public_lockbit_rules.xml"
$demoRuleSource = Join-Path $PSScriptRoot "wazuh\\custom_rules\\ransomware_demo_rules.xml"
$demoRuleTarget = "/var/ossec/etc/rules/ransomware_demo_rules.xml"
$decoderSource = Join-Path $PSScriptRoot "wazuh\\custom_decoders\\ransomware_demo_decoders.xml"
$decoderTarget = "/var/ossec/etc/decoders/ransomware_demo_decoders.xml"
$snippet = @'
<ossec_config>
  <localfile>
    <log_format>json</log_format>
    <location>/var/ossec/logs/replay/live_demo.jsonl</location>
  </localfile>
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/ossec/logs/replay/demo_simulation.log</location>
  </localfile>
</ossec_config>
'@

docker cp $ruleSource "${container}:$ruleTarget" | Out-Null
docker cp $demoRuleSource "${container}:$demoRuleTarget" | Out-Null
docker cp $decoderSource "${container}:$decoderTarget" | Out-Null

docker exec $container sh -lc "mkdir -p /var/ossec/logs/alerts /var/ossec/logs/archives /var/ossec/logs/firewall && chown -R wazuh:wazuh /var/ossec/logs"
docker exec $container sh -lc "mkdir -p /var/ossec/logs/replay && : > /var/ossec/logs/replay/live_demo.jsonl && chown wazuh:wazuh /var/ossec/logs/replay/live_demo.jsonl"
docker exec $container sh -lc ": > /var/ossec/logs/replay/demo_simulation.log && chown wazuh:wazuh /var/ossec/logs/replay/demo_simulation.log"

$existing = docker exec $container sh -lc "grep -F '/var/ossec/logs/replay/live_demo.jsonl' /var/ossec/etc/ossec.conf >/dev/null && echo PRESENT || echo MISSING"
$demoExisting = docker exec $container sh -lc "grep -F '/var/ossec/logs/replay/demo_simulation.log' /var/ossec/etc/ossec.conf >/dev/null && echo PRESENT || echo MISSING"

if (($existing -match "MISSING") -or ($demoExisting -match "MISSING")) {
  $encoded = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($snippet))
  docker exec $container sh -lc "echo $encoded | base64 -d >> /var/ossec/etc/ossec.conf"
}

docker restart $container | Out-Null
Write-Output "Live manager configured."
