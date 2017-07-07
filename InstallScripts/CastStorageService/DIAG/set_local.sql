create or replace function  SET_Psft_Secu_CustomMetrics  (I_SET_ID int)
returns int
as
$body$
declare
ERRORCODE	INT := 0;
begin
/* Set name SET_Psft_Secu_CustomMetrics */
  insert into SET_Contents (SetId, ObjectId)
  select distinct I_SET_ID, o.OBJECT_ID
  from CTT_OBJECT_APPLICATIONS o where o.OBJECT_TYPE in 
	(select IdTyp from TypCat where IdCatParent in                    
  		(select IdCat from Cat where CatNam in ('PSoft_PCodeEvent','PSoft_PCodeMethods','PSoft_PCodeFunctions')));
Return ERRORCODE;
end;
$body$
LANGUAGE plpgsql
/

