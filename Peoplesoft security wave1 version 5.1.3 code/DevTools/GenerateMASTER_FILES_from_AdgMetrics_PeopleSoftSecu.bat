@echo on
MODE CON: COLS=132 LINES=40

::Parameters to adapt to each analysis env :
Set SourceFolder=C:\SOURCES\DEV\com.castsoftware.uc.peoplesoft.security\DevTools
Set TargetFolder=C:\SOURCES\DEV\com.castsoftware.uc.peoplesoft.security\MasterFiles
Set adgMetrics=AdgMetrics_PSFT_SECU_004.xml

::Parameters to adapt in some cases :
Set MetricsCompiler_BAT_path=.\MetricsCompiler.bat


Title Generating MASTER FILES in %TargetFolder% from %adgMetrics% 

:: call Compiler - full syntax (with specific AdgConfigData file name)
call %MetricsCompiler_BAT_path% -decodeUA -inputdir %SourceFolder% -outputdir %TargetFolder% -filename %adgMetrics% 
rem 2>> log2.txt

::TOBE : Manage ERRORLEVEL ?
pause