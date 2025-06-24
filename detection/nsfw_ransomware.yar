
rule NSFW_Ransomware_EncodedPowerShell
{
    meta:
        author = "Q / AP3X"
        description = "Detects base64 encoded PowerShell usage typical of NSFW-Ransomware"
        reference = "https://github.com/P1rat3L00t/NSFW-Ransomware"
    strings:
        $ps1 = "powershell -EncodedCommand"
    condition:
        $ps1
}
