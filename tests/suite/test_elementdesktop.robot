*** Settings ***
Documentation    Test cases for element-desktop snap
Resource         kvm.resource


*** Test Cases ***
Element Desktop Launches And Renders
    [Documentation]    Verify element-desktop snap launches and renders a UI on Mir
    [Tags]    smoke    yarf:certification_status: blocker
    Log Screenshot
