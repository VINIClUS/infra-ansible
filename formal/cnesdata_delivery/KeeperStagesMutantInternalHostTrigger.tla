---------------- MODULE KeeperStagesMutantInternalHostTrigger ----------------
EXTENDS KeeperStages

InternalHostTriggerRows ==
    [i \in DOMAIN ModelTriggerRows |->
        IF ModelTriggerRows[i][1] = "api"
        THEN <<"api", "host", "internal", "static">>
        ELSE ModelTriggerRows[i]]

=============================================================================
