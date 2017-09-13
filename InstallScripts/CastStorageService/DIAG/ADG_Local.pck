<?xml version="1.0" encoding="iso-8859-1"?>
<Package PackName="ADG_LOCAL_Psft_Secu" Type="INTERNAL" Version="1.0.0.2" SupportedServer="ALL" Display="ADG on Local for Psft_Secu" DatabaseKind="KB_LOCAL" Description="">
	<Include>
	</Include>
	<Exclude>
	</Exclude>
	<Install>
	</Install>
	<Refresh>
        <Step Type="PROC" File="set_local.sql"></Step>
		<Step Type="DATA" File="set_data.xml" Model="set_tables.xml" Scope="OBJSETINIT"></Step>
	</Refresh>
	<Remove>
	</Remove>
</Package>