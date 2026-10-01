*** Settings ***
Library    SSHLibrary
Resource    idp.resource
Suite Setup    Skip without the module

*** Test Cases ***
Check if idp is removed correctly
    ${rc} =    Execute Command    remove-module --no-preserve ${module_id}
    ...    return_rc=True    return_stdout=False
    Should Be Equal As Integers    ${rc}    0

Remove the user domain
    ${ldap_module_id} =    Get Variable Value    ${ldap_module_id}    ${EMPTY}
    Skip If    not $ldap_module_id    The user domain was not created
    Execute Command    redis-cli --no-auth-warning hdel cluster/module_domains fakeapp1
    Run task    cluster/remove-internal-domain    {"domain": "${USER_DOMAIN}"}    decode_json=${FALSE}
