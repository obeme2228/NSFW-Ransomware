
# Install Sysmon with custom config
.\Sysmon64.exe -i .\sysmon-config.xml -accepteula

# Validate Sigma rules with sigmac (example for Splunk)
sigmac -t splunk -c splunk-windows multi_vector_malware_activity.yml

