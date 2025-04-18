/*********************************************************************\
*                                                                      
* Module Name: ISPERROR.H                                              
*                                                                      
* OS/2 Dialog Manager error constants for user applications.           
*                                                                      
* (c) Copyright IBM Corproation, 1989. All rights reserved.            
*                                                                      
\*********************************************************************/

#ifndef ISPERROR_H
#define ISPERROR_H


/* Dialog Manager Error Constants */

#define DMERR_BASE_ERROR_CLASS           100000L
#define DMERR_INFORMATIONAL              0L
#define DMERR_LOW_WARNING                400000L
#define DMERR_HIGH_WARNING               800000L
#define DMERR_PROGRAMMER_ERROR           1200000L
#define DMERR_RESOURCE_FAILURE           1600000L
#define DMERR_SEVERE_ERROR               2000000L

/* ISPCI/ISPCI2 Error Constants */

#define DMERR_INVALID_HWND               1200100L
#define DMERR_UPPERCASE                  1200101L
#define DMERR_UPPERCASE_BUFFER           1200102L
#define DMERR_UPPERCASE_VERB             1200103L
#define DMERR_UNEXPECTED_PAREN           1200104L
#define DMERR_BUF_TOO_LONG               1200105L
#define DMERR_INVALID_SERVICE_PARM       1200106L
#define DMERR_TOO_MANY_PARMS             1200107L
#define DMERR_SUBFIELD                   1200108L
#define DMERR_INVALID_KEYWORD            1200109L
#define DMERR_SUBFIELD_MISSING           1200110L
#define DMERR_PARM_MISSING               1200111L
#define DMERR_POSITIONAL_MISSING         1200112L
#define DMERR_INVALID_PARM_LENGTH        1200113L
#define DMERR_LIST_FOUND                 1200114L
#define DMERR_NAME_LIST                  1200115L
#define DMERR_KEYWORD_CONFLICT           1200116L
#define DMERR_CMD_SERVICE                1200117L
#define DMERR_STRING_END                 1200118L
#define DMERR_END_BUFFER_FOUND           1200119L
#define DMERR_SUBSCRIPT_INVALID          1200120L
#define DMERR_ISPCI2_CALL                1200121L
#define DMERR_GET_SUBSTITUTE_VAR         1200122L
#define DMERR_MORE_PARMS                 1200123L
#define DMERR_ISPCI_CALL                 1200124L
#define DMERR_BUFFER_EXCEEDS_MAX         1200125L
#define DMERR_SERVICE_NOT_FOUND          1200126L
#define DMERR_SERVICE_NAME_LENGTH        1200127L
#define DMERR_BUFFER_EMPTY               1200128L
#define DMERR_UNEXPECTED_LIST_FOUND      1200129L
#define DMERR_PARM_TOO_LONG              1200130L
#define DMERR_POSITIONAL_NOT_FOUND       1200131L
#define DMERR_NO_POSITIONAL_FOUND        1200132L
#define DMERR_NULL_PARM                  1200133L
#define DMERR_END_BUFF_BEFORE_END_LIST   1200134L
#define DMERR_KEYWORD_NOT_IN_TABLE       1200135L
#define DMERR_INVALID_KEYWORD_LENGTH     1200136L
#define DMERR_INVALID_SUB_KEYWORD        1200137L
#define DMERR_SUBFIELD_NOT_NUMERIC       1200138L
#define DMERR_REQUIRED_SUBFIELD_MISSING  1200139L
#define DMERR_CONVERTING_NUMERIC_PARM    1200140L
#define DMERR_NUMERIC_PARM_RANGE         1200141L
#define DMERR_KEYWORD_TABLE_NOT_FOUND    1600100L

/* Dialog Manager Controls Error Constants */

#define DMERR_LOAD_APPL_CMD_TABLE        505L
#define CMERR_DEFAULT_KEY_TABLE_ENTRY    400500L
#define CMERR_MATCHING_COMMAND_INDEX     400501L
#define CMERR_NO_COMMAND_FOR_KEY         400502L
#define DMERR_COMMAND_STACK_EMPTY        400503L
#define CMERR_PS_INVALID_VALUE           400504L
#define CMERR_DUPLICATE_LF_MOD_ROWS      400505L
#define CMERR_OUT_OF_BOUNDS_POS          800500L
#define CMERR_QUERY_ZPANELID             800501L
#define CMERR_QUERY_ZFKA                 800502L
#define CMERR_UA_DO_ACTION               800505L
#define CMERR_UM_DO_CMD_ACTION           800506L
#define CMERR_UX_DO_XLATE                800507L
#define CMERR_UK_DO_CHECK                800508L
#define CMERR_EXECUTING_SCROLL           800509L
#define CMERR_LMARGIN_EXCEEDS_RMARGIN    800510L
#define CMERR_FONT_NOT_AVAILABLE         800511L
#define CMERR_OVERFLOW_LF_MOD_ROWS       800523L
#define CMERR_USER_DATA_FAILED_XLAT      800524L
#define CMERR_VAR_DATA_TOO_BIG           800525L
#define CMERR_SETTING_POOL_VARIABLE_8     800526L
#define CMERR_GETTING_POOL_VARIABLE_8     800527L
#define CMERR_INVALID_CMDACT_TYPE        1200502L
#define CMERR_DOING_EXT_CMDACT           1200505L
#define CMERR_DOING_INT_CMDACT           1200508L
#define CMERR_INIT_USER_ACTION           1200520L
#define CMERR_INIT_USER_CHECK            1200521L
#define CMERR_INIT_USER_CONTROL          1200522L
#define CMERR_INIT_USER_CMD_ACTION       1200523L
#define CMERR_INIT_USER_XLATE            1200524L
#define CMERR_USER_ACTION_NOT_REG        1200525L
#define CMERR_USER_CHECK_NOT_REG         1200526L
#define CMERR_USER_CONTROL_NOT_REG       1200527L
#define CMERR_USER_CMD_ACTION_NOT_REG    1200528L
#define CMERR_USER_VAR_ACCESS_NOT_REG    1200529L
#define CMERR_USER_XLATE_NOT_REG         1200530L
#define CMERR_FOCUS_DEST_WND_UNDEFINED   1200532L
#define CMERR_FLD_CANNOT_TAKE_FOCUS      1200533L
#define CMERR_ACCEPTING_FOCUS            1200535L
#define CMERR_LF_NUM_OF_ROWS_OUT_RANGE   1200537L
#define CMERR_TOP_ROW_OUT_OF_RANGE       1200539L
#define CMERR_LC_OUTPUT_ONLY_FIELD       1200540L
#define CMERR_LF_MOD_ROW_INVALID         1200542L
#define CMERR_SL_NUMROWS_OUT_OF_RANGE    1200543L
#define CMERR_SL_SELECTED_ROWS_RANGE     1200544L
#define CMERR_SL_TOP_ROW_OUT_OF_RANGE    1200545L
#define CMERR_LOAD_INFO_FONTS            1200546L
#define CMERR_TEXT_LONGER_THAN_WND_MAX   1200547L
#define CMERR_GET_COMMAND_AREA_TEXT      1200549L
#define CMERR_SETTING_POOL_VARIABLE_12   1200550L
#define CMERR_INIT_USER_VARIABLE         1200553L
#define CMERR_GETTING_POOL_VARIABLE_12   1200554L
#define CMERR_PS_NO_MATCH_ON_OUTPUT      1200555L
#define CMERR_VAR_LENGTH_EXCEEDS_BUFFER  1200556L
#define CMERR_INVALID_MSG_PARM_SIZE      1200557L
#define CMERR_ALLOC_AB_TEXT              1600500L
#define CMERR_GETTING_MEM_CMDACT_STRING  1600501L
#define CMERR_SYSTEM_CMD_TABLE_WNDHDL    1600502L
#define CMERR_SCROLLING_BACKWARD         1600504L
#define CMERR_SCROLLING_FORWARD          1600505L
#define CMERR_SCROLLING_LEFT             1600506L
#define CMERR_SCROLLING_RIGHT            1600507L
#define CMERR_SET_LF_EDIT_CTL_NAME       1600508L
#define CMERR_SHOW_PANEL                 1600509L
#define CMERR_POPPING_CMD_STACK          1600510L
#define CMERR_SETTING_POP_CMDSTR         1600511L
#define CMERR_SETTING_ZVERB              1600512L
#define CMERR_SETTING_ZCMD               1600513L
#define CMERR_CANCELING_PANEL            1600514L
#define CMERR_SETTING_REMAIN_CMDS        1600515L
#define CMERR_EXECUTE_ENTER              1600516L
#define CMERR_ENTERING_PANEL             1600517L
#define CMERR_EXITING_PANEL              1600518L
#define CMERR_SETTING_ZPANELID           1600519L
#define CMERR_SETTING_ZFKA               1600520L
#define CMERR_CHANGING_FKA_FORM          1600521L
#define CMERR_SHOW_PANELID               1600522L
#define CMERR_PASSTHRU                   1600523L
#define CMERR_SETVERB                    1600524L
#define CMERR_PUSH_CMD_STRING            1600525L
#define CMERR_SETTING_CMD_TEXT           1600526L
#define CMERR_REFRESHING_AVAILVAR        1600527L
#define CMERR_REFRESHING_SKIPVAR         1600528L
#define CMERR_KEYTBL_ENTRY_UNKNOWN       1600531L
#define CMERR_REFRESHING_CMDACT_STRING   1600532L
#define CMERR_PASSING_EXTERNAL_CMD       1600533L
#define CMERR_PASSING_INTERNAL_CMD       1600534L
#define CMERR_PASSING_KEY_TABLE_ENTRY    1600535L
#define CMERR_EXECUTING_ALIAS            1600536L
#define CMERR_EXTERNAL_CMD               1600537L
#define CMERR_CHILD_NOT_KNOWN            1600538L
#define CMERR_GETTING_MEM_ACTION_PARM1   1600539L
#define CMERR_GETTING_MEM_ACTION_PARM2   1600540L
#define CMERR_GETTING_MEM_VARIABLE_STR   1600541L
#define DMERR_ALLOC_COMMAND_POOL         1600542L
#define DMERR_GET_GBL_INSTANCE_MEM       1600543L
#define DMERR_GET_INSTANCE_MEM           1600544L
#define DMERR_GET_APPL_DATA_ENTRY_MEM    1600545L
#define DMERR_REMAIN_CMD_STRING_MEM      1600546L
#define DMERR_GET_CMD_STACK_NODE_MEM     1600547L
#define DMERR_GET_CMD_STACK_MEM          1600548L
#define CMERR_PASSING_EXT_CMD_STRING     1600549L
#define CMERR_SETTING_SET_VAR            1600550L
#define CMERR_NOTIFY_SETVAR_CHG          1600551L
#define CMERR_SETTING_TOGGLE_VAR         1600552L
#define CMERR_NOTIFY_TOGVAR_CHG          1600553L
#define CMERR_QUERY_CMD_TABLE_WNDHDL     1600554L
#define CMERR_LOADING_KEY_LIST           1600555L
#define CMERR_GETTING_KEY_LIST           1600556L
#define CMERR_CREATING_KEY_LIST          1600557L
#define CMERR_QUERY_DMKEY_TABLE_INFO     1600558L
#define CMERR_SETTING_ACTION_PARM1       1600560L
#define CMERR_SETTING_ACTION_PARM2       1600561L
#define CMERR_SETTING_VARIABLE           1600562L
#define DMERR_EXECUTE_TUTORIAL           1600563L
#define DMERR_LOAD_DEF_CMD_TABLE         1600564L
#define DMERR_CREATE_DEF_CMD_TABLE       1600565L
#define DMERR_LOAD_CMD_TABLE             1600566L
#define DMERR_CREATE_APPL_CMD_TABLE      1600567L
#define CMERR_RUN_CMD                    1600568L
#define CMERR_DOING_PANEL_ACTION         1600570L
#define CMERR_EXECUTING_KEY_ACTION       1600571L
#define CMERR_LC_XLATE_VALUE             1600572L
#define CMERR_UPDATE_LC_DATA             1600573L
#define CMERR_QUERY_LC_ARRAY_VALUE       1600574L
#define CMERR_LF_VARIABLE_CHANGED        1600575L
#define CMERR_ALLOC_LC_DATA              1600576L
#define CMERR_ALLOC_MODIFIED_ROWS_FLAGS  1600577L
#define CMERR_CELL_EDIT_TEXT_LIMIT       1600578L
#define CMERR_REPOSITION_LF              1600579L
#define CMERR_QUERY_LF_MOD_ROWS          1600580L
#define CMERR_UPDATE_LF_MOD_ROWS         1600581L
#define CMERR_ALLOC_TRANSLATE_BUFFER     1600582L
#define CMERR_AB_ATTRIB_FAILED           1600583L
#define CMERR_SETTING_PANEL_VARIABLE     1600585L
#define CMERR_GETTING_PANEL_VARIABLE     1600587L
#define CMERR_GETTING_MEM_VAR_BUFFER     1600588L
#define CMERR_GETTING_CHANGED_VAR        1600589L
#define CMERR_SETTING_CHANGED_VAR        1600590L
#define CMERR_SET_INST_MIN_MAX_SIZE      1600591L
#define CMERR_GETTING_USER_CMDACT_PARM   1600592L
#define CMERR_USER_ACTION_PARM_ALLOC     1600593L
#define CMERR_USER_CMD_ACT_PARM_ALLOC    1600594L
#define CMERR_USER_CONTROL_PARM_ALLOC    1600595L
#define CMERR_PS_DISPLAY_DM_MESSAGE      1600596L
#define CMERR_PS_UPDATE_PANEL            1600597L
#define CMERR_COMMAND_TEXT               1600598L
#define CMERR_NO_KEY_TABLE               1600599L
#define CMERR_NO_FKA_CREATED             1600600L
#define CMERR_DIV_SET_MIN_MAX_SIZE       1600601L
#define CMERR_DIV_GPI_SET_ATTRS          1600602L
#define CMERR_DIV_GPI_SET_CUR_POS        1600603L
#define CMERR_DIV_GPI_LINE               1600604L
#define CMERR_BUTTON_ACCEPTING_FOCUS     1600605L
#define CMERR_AR_QRY_REGION_MIN_CX       1600606L
#define CMERR_NO_MEMORY                  1600607L
#define CMERR_PAINT_INFO_TEXT            1600608L
#define CMERR_FONT_METRICS_QRY_PROBLEM   1600609L
#define CMERR_INFO_CHAR_ATTRS_PROBLEM    1600610L
#define CMERR_ALLOC_TEXT_ATTR_POS_LIST   1600611L
#define CMERR_ALLOC_TEXT_ATTR_POS_ARRAY  1600612L
#define CMERR_ALLOC_INFO_FORMAT_TABLE    1600613L
#define CMERR_ALLOC_INFO_ATTR_ARRAY      1600614L
#define CMERR_INVALID_TEXT_ATTRIBUTE     1600615L
#define CMERR_ALLOC_FONT_METRICS_BUF     1600616L
#define CMERR_ALLOC_MARGIN_ARRAY         1600618L
#define CMERR_MAX_FONTS_LOADED           1600619L
#define CMERR_INVALID_SYS_CMDACT         1600620L
#define CMERR_CMD_ACTION_UNSPECIFIED     1600621L
#define CMERR_DOING_USER_CMDACT          1600622L
#define CMERR_INVALID_ACTION_TYPE        1600623L
#define CMERR_SET_VAR_UNSPECIFIED        1600624L
#define CMERR_TOGGLE_VAR_UNSPECIFIED     1600625L
#define CMERR_MEM_SIZE_LIST              1600626L
#define CMERR_PROCESSING_BACKTAB         1600628L
#define CMERR_PROCESSING_TAB             1600629L
#define CMERR_PROCESSING_VK_TAB          1600630L
#define CMERR_RUN_CMD_UNSPECIFIED        1600631L
#define CMERR_NOTIFY_VAR_CHANGE          1600632L
#define CMERR_ACTION_BAR_UNDEFINED       1600633L
#define CMERR_LC_ROW_OUT_OF_RANGE        1600634L
#define CMERR_DF_DISPLAY_DM_MESSAGE      1600635L
#define CMERR_ALLOC_MEMORY               1600636L
#define CMERR_SET_TEXT_LIMIT             1600637L
#define CMERR_EF_ACCEPTING_FOCUS         1600638L
#define CMERR_UPDATE_SL_SELECTED_ROWS    1600639L
#define CMERR_QUERY_SC_ARRAY_VALUE       1600640L
#define CMERR_ALLOC_SL_XLATE_BUFFER      1600641L
#define CMERR_SC_XLATE_VALUE             1600642L
#define CMERR_INSERT_SL_ITEM             1600643L
#define CMERR_QUERY_SL_SELECTED_ROWS     1600644L
#define CMERR_ALLOC_FONT_DESCRIPTORS     1600645L
#define CMERR_MODIFIED_ROWS_INDEX_RANGE  1600646L
#define CMERR_ALLOC_SF_WORK_BUFFER       1600676L
#define CMERR_ALLOC_SF_CHECK_TEXT        1600677L
#define CMERR_SET_SF_BUTTON_TEXT         1600678L
#define CMERR_SF_CHANGE_CHECK_VALUE      1600679L
#define CMERR_GET_COUNTRY_INFO           1600681L
#define CMERR_CREATE_KEY_ACCELTABLE      1600682L
#define CMERR_SET_KEY_ACCELTABLE         1600683L
#define CMERR_KEY_LIST_UNSPECIFIED       1600684L
#define CMERR_DF_OUTPUT_REPOSITION       1600687L
#define CMERR_LOADING_CHGDEFS_PANEL      1600688L
#define CMERR_ADDING_CHGDEFS_POPUP       1600689L
#define CMERR_DISPLAYING_CHGDEFS         1600690L
#define CMERR_REMOVING_CHGDEFS_POPUP     1600691L
#define CMERR_DEFINING_CHGDEFS_VARS      1600692L
#define CMERR_GETTING_CHGDEFS_VARS       1600693L
#define CMERR_PUTTING_CHGDEFS_VARS       1600694L
#define CMERR_DELETING_CHGDEFS_VARS      1600695L
#define CMERR_DEFACT_IN_PROGRESS         1600696L
#define CMERR_QUERY_DEFAULT_ACTION       1600697L
#define CMERR_SET_TITLEBAR_TEXT          1600698L
#define CMERR_CT_DISPLAY_DM_MESSAGE      1600699L
#define CMERR_PS_MEM_ALLOC               1600700L
#define DMERR_CMD_TABLE_UNAVAILABLE      1600701L
#define CMERR_DOING_USER_ACTION          1600702L
#define DMERR_CLASS_REGISTRATION_FAILED  2000506L
#define CMERR_SETTING_POOL_VARIABLE_20   2000515L
#define CMERR_GETTING_POOL_VARIABLE_20   2000516L

/* Display Services Error Constants */

#define DMERR_PANEL_ENTERED              1700L
#define DMERR_PASSTHRU                   1701L
#define DMERR_SETVERB                    1702L
#define DMERR_PANEL_CANCELED             401700L
#define DMERR_PANEL_EXITED               801700L
#define DMERR_QUERY_ZHELP_WND_TITLE      801701L
#define DMERR_QUERY_ZPRIMARY_WND_TITLE   801702L
#define DMERR_SET_FKA_FORM               801703L
#define DMERR_SET_PANEL_ID_VISIBILITY    801704L
#define DMERR_FORCEXIT_INVOKED           801705L
#define DMERR_FORCEXIT_INVALID_WNDHDL    1201700L
#define DMERR_FORCEXIT_INVALID_SET       1201701L
#define DMERR_FORCEXIT_INVALID_DMCOMM    1201702L
#define DMERR_NO_PRIOR_DISPLAY           1201703L
#define DMERR_INVALID_ADDPOP             1201704L
#define DMERR_NO_POPUPS_EXIST            1201705L
#define DMERR_ADDPOP_BEFORE_PRIMARY_WND  1201708L
#define DMERR_ADDPOP_UNKNOWN_FIELD_NAME  1201709L
#define DMERR_ADDPOP_NO_PREV_DISPLAY     1201710L
#define DMERR_MSGLOC_UNKNOWN_FIELD_NAME  1201711L
#define DMERR_FORCEXIT_DISPLAY_FAILED    1601700L
#define DMERR_CREATE_PRIMARY_WND_ICON    1601701L
#define DMERR_GET_PRIMARY_WND_ICON       1601702L
#define DMERR_GET_PANEL_TEMPLATE         1601703L
#define DMERR_CREATE_PANEL               1601704L
#define DMERR_PANEL_ENTER_PROCESSING     1601705L
#define DMERR_CREATE_FRAME               1601706L
#define DMERR_UPDATE_PANEL               1601707L
#define DMERR_SET_PANEL_HELP_INFO        1601708L
#define DMERR_ALLOC_PANEL_MGR_INST_DATA  1601709L
#define DMERR_CREATE_FRAME_CONTROL       1601710L
#define DMERR_ALLOC_PANEL_MGR_POOL       1601711L
#define DMERR_ALLOC_PANEL_INST_DATA      1601712L
#define DMERR_GPI_QUERY_TEXT_WIDTH       1601713L
#define DMERR_CONVERT_INSTANCE_DATA      1601714L

/* Help Interface Error Constants */

#define DMERR_EXT_HELP_PANEL_UNDEFINED   1202100L
#define DMERR_KEYS_HELP_UNDEFINED        1202101L
#define DMERR_UNABLE_TO_LOAD_FONTS       1202138L
#define DMERR_DMOPEN_LOAD_FONTS          1202139L
#define DMERR_SET_LIBDEF_HELP_LIBRARIES  1602101L
#define DMERR_SET_HELP_SHOW_PAN_IDS      1602102L
#define DMERR_DISPLAY_EXT_HELP_PANEL     1602103L
#define DMERR_DISPLAY_KEYS_HELP_PANEL    1602104L
#define DMERR_QUERY_ZKEYHELP_PROBLEM     1602105L
#define DMERR_EXECUTING_HELP_TUTORIAL    1602106L
#define DMERR_ALLOC_HIC_LOCAL_INST_DATA  1602111L
#define DMERR_ALLOC_HIC_GBL_INST_DATA    1602112L
#define DMERR_ALLOC_HIC_HELPTABLE        1602113L
#define DMERR_ALLOC_HIC_HELPSUBTABLE     1602114L
#define DMERR_CREATE_HELP_INSTANCE       1602116L
#define DMERR_ALLOC_EXT_HLP_NAME_BUFFER  1602120L
#define DMERR_ASSOC_PAN_WITH_HELP_INST   1602121L
#define DMERR_SET_HELP_ACTIVE_WINDOW     1602122L
#define DMERR_SET_HELP_LIB_NAMES         1602123L
#define DMERR_SET_HELP_WND_TITLE         1602125L
#define DMERR_DISPLAY_HELP_PANEL         1602127L
#define DMERR_QRY_ACTION_BAR_HELP        1602128L
#define DMERR_QRY_HELP_PANEL_NAME        1602129L
#define DMERR_PROCESS_HELP_DISPLAY       1602130L
#define DMERR_PROCESS_KEYS_HELP_ON_FKA   1602131L
#define DMERR_PROCESS_DEFAULT_EXT_HELP   1602132L
#define DMERR_ALLOC_NEW_HELP_LIB_NAMES   1602135L
#define DMERR_DISPLAY_HIC_ERROR_MESSAGE  1602136L
#define DMERR_QUERY_HELP_LIBRARIES       1602137L
#define DMERR_DISPLAY_HELP_FOR_HELP      1602140L

/* DMOPEN/DMCLOSE Error Constants */

#define DMERR_STARTING_TRACE             1202903L
#define DMERR_INVALID_UNIQUE_PARM        1202901L
#define DMERR_INVALID_DMCOMM_CLOSE       1202902L
#define DMERR_SEMAPHORE_COMPID           1602900L
#define DMERR_DMI_CLOSE_FAILED           1602901L
#define DMERR_CREATE_SPACE_START         2002900L
#define DMERR_CREATE_POOL_START          2002901L
#define DMERR_GET_HEADER_START           2002902L
#define DMERR_FAILED_STARTUP_DIMVALID    2002903L
#define DMERR_SHARE_SEGS_DIMVALID        2002904L
#define DMERR_GET_IID_DIMADD             2002906L
#define DMERR_INVALID_DMCOMM_DIMADD      2002907L
#define DMERR_INVALID_DMCOMM_DIMDEL      2002908L
#define DMERR_GET_PROC_DIMSH             2002909L
#define DMERR_GIVE_SEG_DIMSH             2002910L
#define DMERR_INVALID_DMCOMM             2002911L
#define DMERR_APPLID_UPPER_CASE          2002912L
#define DMERR_PM_INITIALIZE              2002913L
#define DMERR_CREATE_MSG_QUEUE           2002914L
#define DMERR_GET_SPACE_DATA_OPEN        2002915L
#define DMERR_DIM_ADD_FAILED             2002916L
#define DMERR_EXLST_ADD_OPEN             2002917L
#define DMERR_GET_SPACE_HAB_OPEN         2002918L
#define DMERR_GET_SPACE_IID_OPEN         2002919L
#define DMERR_DMI_OPEN_FAILED            2002920L
#define DMERR_NLS_ERROR_OPEN             2002921L
#define DMERR_PARM_MISSING_OPEN          2002922L
#define DMERR_INVALID_APPLID             2002923L
#define DMERR_INVALID_THREAD_ID          2002924L
#define DMERR_INVALID_INSTID             2002925L
#define DMERR_CANNOT_CREATE_INSTID       2002926L
#define DMERR_CANNOT_CREATE_OBJ_WND      2002927L
#define DMERR_EXLST_REMOVE_FAILED        2002928L
#define DMERR_DIM_DEL_FAILED             2002929L
#define DMERR_DM_CLASS_REGISTRATION      2002930L

/* Library Services Error Constants */

#define DMERR_APP_LIBDEF_FILE_NOT_FOUND  3300L
#define DMERR_LIBDEF_COMMAND_TOO_LONG    1203300L
#define DMERR_LIBRARY_EXISTS             1203301L
#define DMERR_HELP_EXISTS                1203302L
#define DMERR_KEYLIST_MEMBER_NOT_FOUND   1203303L
#define DMERR_ICON_MEMBER_NOT_FOUND      1203304L
#define DMERR_MESSAGE_MEMBER_NOT_FOUND   1203305L
#define DMERR_DM_PNL_MEMBER_NOT_FOUND    1203306L
#define DMERR_COMMAND_MEMBER_NOT_FOUND   1203307L
#define DMERR_INVALID_LIBDEF_IN_APP      1203308L
#define DMERR_UNMATCHED_QUOTATION_MARK   1203309L
#define DMERR_INVALID_LIBLIST            1203310L
#define DMERR_OPEN_APP_FILE              1603300L
#define DMERR_READ_APP_FILE              1603301L
#define DMERR_OPEN_KEYLIST_LIBRARY       1603302L
#define DMERR_OPEN_ICON_LIBRARY          1603303L
#define DMERR_OPEN_MESSAGE_LIBRARY       1603304L
#define DMERR_OPEN_DM_PNL_LIBRARY        1603305L
#define DMERR_OPEN_COMMAND_LIBRARY       1603306L
#define DMERR_GET_KEYLIST_LIBRARY_DIR    1603307L
#define DMERR_GET_ICON_LIBRARY_DIR       1603308L
#define DMERR_GET_MESSAGE_LIBRARY_DIR    1603309L
#define DMERR_GET_DM_PNL_LIBRARY_DIR     1603310L
#define DMERR_GET_COMMAND_LIBRARY_DIR    1603311L
#define DMERR_GET_KEYLIST_MEMBER         1603312L
#define DMERR_GET_ICON_MEMBER            1603313L
#define DMERR_GET_MESSAGE_MEMBER         1603314L
#define DMERR_GET_DM_PNL_MEMBER          1603315L
#define DMERR_GET_COMMAND_MEMBER         1603316L
#define DMERR_LIBRARY_CHANGED            1603317L
#define DMERR_ALLOC_LIBRARY_DMOPEN       1603318L
#define DMERR_ALLOC_FILE_READ_BUFFER     1603319L
#define DMERR_ALLOC_NEW_LIBLIST          1603320L

/* Message Services Error Constants */

#define DMERR_QUERY_MESSAGE_ID_VISIBLE   403700L
#define CMERR_MESSAGE_TRUNCATED          803700L
#define CMERR_MESSAGE_NOT_FOUND          1203700L
#define DMERR_DISPLAY_MESSAGE_PANEL      1603700L
#define DMERR_ADD_MESSAGE_POPUP          1603701L
#define DMERR_CREATE_MESSAGE_PANEL       1603702L
#define DMERR_ALLOC_MESSAGE_ID           1603703L
#define DMERR_LOAD_MESSAGE_PANEL_RSC     1603704L
#define DMERR_CREATE_TEXT_CONTROL        1603705L
#define DMERR_SHOW_CURRENT_PANEL         1603706L
#define DMERR_REMOVE_MESSAGE_PANEL       1603707L
#define DMERR_SET_MESSAGE_TEXT           1603708L
#define DMERR_SET_ZVAR_RETURN_CODE       1603709L
#define DMERR_ALLOC_INSTANCE_DATA        1603710L
#define DMERR_ALLOC_SESSION_INST_DATA    1603711L
#define DMERR_ALLOC_CRTCL_MESSAGE_TEXT   1603712L
#define DMERR_LOAD_MESSAGE_RESOURCE      1603713L
#define DMERR_CREATE_MSG_CONTROL         1603714L
#define DMERR_GET_MESSAGE_RESOURCE       1603715L
#define DMERR_GET_MESSAGE                1603716L
#define DMERR_ALLOC_MSG_TEXT_REQUEST     1603717L
#define CMERR_REFRESH_VARIABLE           1603718L
#define CMERR_TRANSLATE_MSG_VARIABLE     1603719L
#define DMERR_CREATE_SEVERE_PANEL        1603720L
#define DMERR_LOAD_SEVERE_MSG_DLGBOX     1603721L
#define DMERR_CREATE_ACCEL_TABLE         1603722L
#define DMERR_SET_ACCEL_TABLE            1603723L
#define CMERR_ALLOC_MSG_SUB_BUFFER       1603724L
#define CMERR_ALLOC_VAR_XLAT_BUFFER      1603725L
#define DMERR_UPDATE_MESSAGE_PANEL       1603726L
#define DMERR_SET_MSGBOX_TITLE           1603727L
#define DMERR_SET_BUTTON_TEXT            1603728L

/* Storage Manager Error Constants */

#define DMERR_STORAGE                    1604100L
#define DMERR_ALLOCATING_SEGMENT         1604101L
#define DMERR_ALLOC_INTERNAL_CAT         1604102L
#define DMERR_ALLOC_STORAGE_REQUEST      1604103L
#define DMERR_ALL_SEGMENTS_NOT_FREED     1604104L
#define DMERR_COMBINED_BLOCKS_LST        1604105L
#define DMERR_DELETING_POOL              1604106L
#define DMERR_DELETING_SAT_STORAGE       1604107L
#define DMERR_EXPANDING_POOL             1604108L
#define DMERR_FREEING_CHAIN_LINK         1604109L
#define DMERR_FREEING_POOLS_BLOCK        1604110L
#define DMERR_FREEING_POOLS_LST          1604111L
#define DMERR_FREEING_SEGMENT            1604112L
#define DMERR_GETTING_LST_STORAGE        1604113L
#define DMERR_GETTING_STORAGE_BLOCK      1604114L
#define DMERR_INITIALIZING_SEGMENT       1604115L
#define DMERR_INVALID_STORAGE_LENGTH     1604116L
#define DMERR_OVERLAPPING_STORAGE        1604117L
#define DMERR_REQUEST_TOO_LARGE          1604118L
#define DMERR_SEGLINK_NOT_ALLOCATED      1604119L
#define DMERR_SEGMENT_NOT_IN_CHAIN       1604120L
#define DMERR_SHARING_ANCHOR_SEGMENT     1604121L
#define DMERR_SHARING_STORAGE_SEGMENT    1604122L
#define DMERR_STORAGE_NOT_IN_POOL        1604123L
#define DMERR_SUBFREEING_STORAGE         1604124L
#define DMERR_ADDING_AVAILABLE_LIST      2004100L
#define DMERR_ALLOCATING_FIRST_BLOCK     2004101L
#define DMERR_ALLOCATING_FIRST_CAT       2004102L
#define DMERR_ALLOCATING_FIRST_LST       2004103L
#define DMERR_ALLOC_INIT_SPACE           2004104L
#define DMERR_CREATING_DEFAULT_POOL      2004105L
#define DMERR_CREATING_INTERNAL_POOL     2004106L
#define DMERR_CREATING_SEGLINK_POOL      2004107L
#define DMERR_EXISTING_BLOCKS_LST        2004108L

/* Variable Services Error Constants */

#define DMERR_VAR_NOT_FOUND              805300L
#define DMERR_VDELETE_VAR_NOT_FOUND      805301L
#define DMERR_VCOPY_VAR_NOT_FOUND        805302L
#define DMERR_NOT_A_NUMBER               805303L
#define DMERR_INDEFINITE                 805304L
#define DMERR_NEG_INFINITY               805305L
#define DMERR_POS_INFINITY               805306L
#define DMERR_FLOAT_NUM_TOO_LARGE        805307L
#define DMERR_DATA_TRUNC                 805308L
#define DMERR_BINSTR_DATA_TRUNC          805309L
#define DMERR_FIXED_NUM_TOO_LARGE        805310L
#define DMERR_FIXEDU_NUM_TOO_LARGE       805311L
#define DMERR_FIXEDS_NUM_TOO_LARGE       805312L
#define DMERR_HEX_NUM_TOO_LARGE          805313L
#define DMERR_PACK_NUM_TOO_LARGE         805314L
#define DMERR_BIT_NUM_TOO_LARGE          805315L
#define DMERR_UNDERFLOW                  805316L
#define DMERR_OVERFLOW                   805317L
#define DMERR_FIXED_CONVERSION           805318L
#define DMERR_FIXEDS_CONVERSION          805319L
#define DMERR_FIXEDU_CONVERSION          805320L
#define DMERR_HEX_CONVERSION             805321L
#define DMERR_PACK_CONVERSION            805322L
#define DMERR_BIT_CONVERSION             805323L
#define DMERR_FLOAT_CONVERSION           805324L
#define DMERR_UNSIGNED_FIX_FORMAT        805325L
#define DMERR_NOT_A_PACK_NUMBER          805326L
#define DMERR_VCOPY_DATA_TRUNC           805327L
#define DMERR_INVALID_VAR_NAME           1205300L
#define DMERR_INVALID_VDEFINE_VAR_NAME   1205301L
#define DMERR_INVALID_VDELETE_VAR_NAME   1205302L
#define DMERR_INVALID_VCOPY_VAR_NAME     1205303L
#define DMERR_INVALID_VREPLACE_VAR_NAME  1205304L
#define DMERR_INVALID_DIMEN              1205305L
#define DMERR_INVALID_VDEFINE_COPY       1205306L
#define DMERR_INVALID_PACK_DIGITS        1205307L
#define DMERR_INVALID_FLOAT_DIGITS       1205308L
#define DMERR_PACK_NUM_LENGTH_TOO_SMALL  1205309L
#define DMERR_INVALID_SUB                1205310L
#define DMERR_VAR_SUB_NOT_DEFINED        1205311L
#define DMERR_VAR_SUB_INCORRECT_FORMAT   1205312L
#define DMERR_INVALID_SUB_VALUE          1205313L
#define DMERR_SUB_VAR_NOT_ADDED          1205314L
#define DMERR_SUB_OUT_OF_RANGE           1205315L
#define DMERR_VAR_NOT_ARRAY              1205316L
#define DMERR_INVALID_VREPLACE_LENGTH    1205317L
#define DMERR_INVALID_VCOPY_LENGTH       1205318L
#define DMERR_INVALID_VDEFINE_LENGTH     1205319L
#define DMERR_INVALID_PLACE_HOLDER       1205320L
#define DMERR_NAME_FORMAT_LIST           1205321L

/* NLS Error Constants */

#define DMERR_SPLT_DBCS_DATA_TRUNC        805700L
#define DMERR_SPLT_DBCS_CHAR              805701L
#define DMERR_NLS_GETCTRYINFO            1605701L
#define DMERR_NLS_CASEMAP                1605702L

/* REXX Interface Error Constants */

#define DMERR_DMCOMM_INVALID_NAME        1206200L
#define DMERR_NO_PM_SESSION              1606200L
#define DMERR_REXX_VARPOOL_ACCESS        1606201L

#endif
