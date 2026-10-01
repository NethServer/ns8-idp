*** Settings ***
Library    SSHLibrary
Resource    idp.resource
Suite Setup    Check the scenario

*** Variables ***
${IMAGE_URL}    ghcr.io/nethserver/idp:latest
${SCENARIO}    install
${ADMIN_USER}    admin
${ADMIN_PASSWORD}    Nethesis,1234

*** Keywords ***
Check the scenario
    Log    Scenario ${SCENARIO} with ${IMAGE_URL}    console=${TRUE}
    IF    r'${SCENARIO}' == 'update'
        ${count} =    Execute Command    api-cli run cluster/list-modules | python3 -c 'import sys, json; print(sum(1 for m in json.load(sys.stdin) if m["id"] == "idp" for v in m["versions"] if not v["testing"]))'
        Skip If    ${count} == 0    The update scenario needs a stable idp release
    END

Services are active
    ${rc} =    Execute Command    runagent -m ${module_id} systemctl --user is-active idp.service postgres.service keycloak.service
    ...    return_rc=True    return_stdout=False
    Should Be Equal As Integers    ${rc}    0

Keycloak runs the module image
    ${expected} =    Execute Command    runagent -m ${module_id} printenv IDP_KEYCLOAK_IMAGE
    ${running} =    Execute Command    runagent -m ${module_id} podman inspect --format {{.ImageName}} keycloak
    Should Not Be Empty    ${expected}
    Should Be Equal    ${running}    ${expected}

OIDC discovery is served through Traefik
    ${output}    ${rc} =    Execute Command    curl -fsk --resolve ${IDP_HOST}:443:127.0.0.1 https://${IDP_HOST}/realms/master/.well-known/openid-configuration
    ...    return_rc=True
    Should Be Equal As Integers    ${rc}    0
    &{discovery} =    Evaluate    json.loads($output)    modules=json
    Should Be Equal    ${discovery.issuer}    https://${IDP_HOST}/realms/master

Login to cluster-admin
    New Page    https://${NODE_ADDR}/cluster-admin/
    Fill Text    text="Username"    ${ADMIN_USER}
    Click    button >> text="Continue"
    Fill Text    text="Password"    ${ADMIN_PASSWORD}
    Click    button >> text="Log in"
    Wait For Elements State    css=#main-content    visible    timeout=10s

*** Test Cases ***
Add module for ${SCENARIO} scenario
    IF    r'${SCENARIO}' == 'update'
        # Install the latest stable release from the software repository
        Set Local Variable    ${iurl}    idp
    ELSE
        Set Local Variable    ${iurl}    ${IMAGE_URL}
    END
    ${output}    ${rc} =    Execute Command    add-module ${iurl} 1
    ...    return_rc=True
    Should Be Equal As Integers    ${rc}    0
    &{output} =    Evaluate    ${output}
    Set Global Variable    ${module_id}    ${output.module_id}

Configure module
    Run task    module/${module_id}/configure-module    {"host": "${IDP_HOST}", "lets_encrypt": false}    decode_json=${FALSE}
    &{config} =    Run task    module/${module_id}/get-configuration    {}
    Should Be Equal    ${config.host}    ${IDP_HOST}
    Should Not Be True    ${config.lets_encrypt}
    ${route} =    Run task    module/traefik1/get-route    {"instance": "${module_id}"}
    Should Be Equal    ${route['host']}    ${IDP_HOST}

Update module
    IF    r'${SCENARIO}' != 'update'
        Skip    Only in the update scenario
    END
    Retry test    OIDC discovery is served through Traefik
    Run task    update-module    {"force": true, "module_url": "${IMAGE_URL}", "instances": ["${module_id}"]}    decode_json=${FALSE}

Check the services
    Retry test    Services are active
    Keycloak runs the module image

Check the OIDC endpoints
    Retry test    OIDC discovery is served through Traefik

Check the admin API credentials
    # The init job has created ns8-agent, and its token is accepted
    ${rc} =    Execute Command    runagent -m ${module_id} python3 -c 'import kcadmin; kcadmin.managed_realms(kcadmin.agent_client())'
    ...    return_rc=True    return_stdout=False
    Should Be Equal As Integers    ${rc}    0

Take screenshots
    [Tags]    ui
    Import Library    Browser
    New Browser    chromium    headless=True
    New Context    ignoreHTTPSErrors=True
    Login to cluster-admin
    Go To    https://${NODE_ADDR}/cluster-admin/#/apps/${module_id}
    Wait For Elements State    iframe >>> h2 >> text="Status"    visible    timeout=10s
    Sleep    5s
    Take Screenshot    filename=${OUTPUT DIR}/browser/screenshot/1._Status.png
    Go To    https://${NODE_ADDR}/cluster-admin/#/apps/${module_id}?page=settings
    Wait For Elements State    iframe >>> h2 >> text="Settings"    visible    timeout=10s
    Sleep    5s
    Take Screenshot    filename=${OUTPUT DIR}/browser/screenshot/2._Settings.png
    Close Browser
