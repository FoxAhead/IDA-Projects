ROBOCOPY "IDA Plugin\mobrule" "%APPDATA%\Hex-Rays\IDA Pro\plugins\mobrule" /MIR /XD .idea /LOG:0-copy_ida_plugin.~log
ROBOCOPY "IDA Plugin" "%APPDATA%\Hex-Rays\IDA Pro\plugins" "MobRulePlugin.py" /IS /LOG+:0-copy_ida_plugin.~log
