ROBOCOPY "IDA Plugin\ascendancy" "%APPDATA%\Hex-Rays\IDA Pro\plugins\ascendancy" /MIR /XD .idea /LOG:0-copy_ida_plugin.~log
ROBOCOPY "IDA Plugin" "%APPDATA%\Hex-Rays\IDA Pro\plugins" "AscendancyPlugin.py" /IS /LOG+:0-copy_ida_plugin.~log
