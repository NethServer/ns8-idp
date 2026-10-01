*** Settings ***
Library    SSHLibrary
Resource    api.resource

*** Variables ***
${IDP_HOST}    idp.fqdn.test
${USER_DOMAIN}    ldap.dom.test

*** Keywords ***
Skip without the module
    # In the update scenario the module is not installed while idp has
    # no stable release
    ${module_id} =    Get Variable Value    ${module_id}    ${EMPTY}
    Skip If    not $module_id    The idp module is not installed

Retry test
    [Arguments]    ${keyword}    @{args}
    Wait Until Keyword Succeeds    60 seconds    2 seconds    ${keyword}    @{args}

Run validation
    [Documentation]    Run an action that must fail validation, and return the first error
    [Arguments]    ${action}    ${input}
    ${errors} =    Run task    ${action}    ${input}    rc_expected=2
    RETURN    ${errors[0]}

Run kccheck
    [Documentation]    Run a check of tests/kccheck.py in the idp module, and return its JSON output
    [Arguments]    @{args}
    Put File    ${CURDIR}/kccheck.py    /tmp/kccheck.py    mode=0644
    ${cmdargs} =    Catenate    @{args}
    ${output}    ${errors}    ${rc} =    Execute Command    runagent -m ${module_id} python3 /tmp/kccheck.py ${cmdargs}
    ...    return_stderr=True    return_rc=True
    Should Be Equal As Integers    ${rc}    0    kccheck.py ${cmdargs} failed:${\n}${errors}
    ${result} =    Evaluate    json.loads($output)    modules=json
    RETURN    ${result}

Login page status
    [Documentation]    Return the HTTP status of the login page of a realm client
    [Arguments]    ${realm}    ${client_id}    ${redirect_uri}
    ${status} =    Execute Command    curl -sk -o /dev/null -w '\%{http_code}' --resolve ${IDP_HOST}:443:127.0.0.1 'https://${IDP_HOST}/realms/${realm}/protocol/openid-connect/auth?client_id=${client_id}&response_type=code&scope=openid&redirect_uri=${redirect_uri}'
    RETURN    ${status}

List realms
    ${response} =    Run task    module/${module_id}/list-realms    {}
    RETURN    ${response['realms']}

Bound domains
    [Arguments]    ${mid}
    ${domains} =    Execute Command    redis-cli --no-auth-warning hget cluster/module_domains ${mid}
    RETURN    ${domains}
