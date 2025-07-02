@description('Name of the Logic App')
param logicAppName string = 'ResetPasswordSessionRevoke-Incident'

@description('Azure subscription ID')
param subscriptionId string

@description('Name of the resource group')
param resourceGroupName string

@description('Azure region for deployment')
param location string = resourceGroup().location

@description('User-assigned managed identity name')
param userAssignedIdentityName string

@description('External resource ID of the Azure Sentinel connection')
param sentinelConnectionExternalId string

@description('External resource ID of the Office 365 connection')
param office365ConnectionExternalId string

@description('Group ID for adding users')
param groupId string = '0de0c985-0472-459f-a964-445f46aaaba1'

@description('Max number of accounts before threshold exceeds')
param threshold int = 10

// Build the full resource IDs from your inputs
var userAssignedIdentityId =  
  '/subscriptions/${subscriptionId}/resourceGroups/${resourceGroupName}' +
  '/providers/Microsoft.ManagedIdentity/userAssignedIdentities/${userAssignedIdentityName}'

var sentinelConnectionId =  
  '/subscriptions/${subscriptionId}/providers/Microsoft.Web/locations/${location}/managedApis/azuresentinel'

var office365ConnectionId =  
  '/subscriptions/${subscriptionId}/providers/Microsoft.Web/locations/${location}/managedApis/office365'

resource logicApp 'Microsoft.Logic/workflows@2017-07-01' = {
  name: logicAppName
  location: location
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: {
      '${userAssignedIdentityId}': {}
    }
  }
  properties: {
    state: 'Enabled'
    definition: {
      $schema: 'https://schema.management.azure.com/providers/Microsoft.Logic/schemas/2016-06-01/workflowdefinition.json#'
      contentVersion: '1.0.0.0'
      parameters: {
        'group-id': {
          type: 'String'
          defaultValue: groupId
        }
        '$connections': {
          type: 'Object'
          defaultValue: {}
        }
      }
      triggers: {
        Microsoft_Sentinel_incident: {
          type: 'ApiConnectionWebhook'
          inputs: {
            host: {
              connection: {
                name: "@parameters('$connections')['azuresentinel']['connectionId']"
              }
            }
            path: '/incident-creation'
            body: {
              callback_url: '@{listCallbackUrl()}'
            }
          }
        }
      }
      actions: {
        'Entities_-_Get_Accounts': {
          type: 'ApiConnection'
          runAfter: {}
          inputs: {
            host: {
              connection: {
                name: "@parameters('$connections')['azuresentinel']['connectionId']"
              }
            }
            method: 'post'
            path: '/entities/account'
            body: '@triggerBody()?[''object'']?[''properties'']?[''relatedEntities'']'
          }
        }
        Threshold: {
          type: 'InitializeVariable'
          runAfter: {
            'Entities_-_Get_Accounts': ['Succeeded']
          }
          inputs: {
            variables: [
              {
                name: 'Threshold'
                type: 'integer'
                value: threshold
              }
            ]
          }
        }
        Initialize_ActionsTaken: {
          type: 'InitializeVariable'
          runAfter: {
            Threshold: ['Succeeded']
          }
          inputs: {
            variables: [
              {
                name: 'ActionsTaken'
                type: 'array'
                value: []
              }
            ]
          }
        }
        Entity_Count: {
          type: 'Compose'
          runAfter: {
            Initialize_ActionsTaken: ['Succeeded']
          }
          inputs: '@length(body(''Entities_-_Get_Accounts'')?[''Accounts''])'
        }
        Within_Threshold: {
          type: 'If'
          runAfter: {
            Entity_Count: ['Succeeded']
          }
          expression: {
            and: [
              {
                lessOrEquals: [
                  '@outputs(''Entity_Count'')',
                  '@variables(''Threshold'')'
                ]
              }
            ]
          }
          actions: {
            For_each: {
              type: 'Foreach'
              foreach: '@body(''Entities_-_Get_Accounts'')?[''Accounts'']'
              actions: {
                Get_UPN: {
                  type: 'Compose'
                  runAfter: {
                    Add_User_to_Group: ['Succeeded']
                  }
                  inputs: '@coalesce(items(''For_each'')?[''additionalData'']?[''UserPrincipalName''], items(''For_each'')?[''additionalData'']?[''UpnName''])'
                }
                Reset_a_password: {
                  type: 'Http'
                  runAfter: {
                    Get_UPN: ['Succeeded']
                  }
                  inputs: {
                    uri: 'https://graph.microsoft.com/v1.0/users/@{outputs(''Get_UPN'')}'
                    method: 'PATCH'
                    body: {
                      passwordProfile: {
                        forceChangePasswordNextSignIn: true
                        forceChangePasswordNextSignInWithMfa: false
                        password: '@{substring(item()?[''ObjectGuid''], 0, 10)}'
                      }
                    }
                    authentication: {
                      type: 'ManagedServiceIdentity'
                      identity: userAssignedIdentityId
                      audience: 'https://graph.microsoft.com'
                    }
                  }
                  runtimeConfiguration: {
                    contentTransfer: {
                      transferMode: 'Chunked'
                    }
                  }
                }
                Revoke_sign_in_session: {
                  type: 'Http'
                  runAfter: {
                    'Send_an_email_(V2)': ['Succeeded']
                  }
                  inputs: {
                    uri: 'https://graph.microsoft.com/v1.0/users/@{outputs(''Get_UPN'')}/revokeSignInSessions'
                    method: 'POST'
                    authentication: {
                      type: 'ManagedServiceIdentity'
                      identity: userAssignedIdentityId
                      audience: 'https://graph.microsoft.com'
                    }
                  }
                  runtimeConfiguration: {
                    contentTransfer: {
                      transferMode: 'Chunked'
                    }
                  }
                }
                Add_User_to_Group: {
                  type: 'Http'
                  inputs: {
                    uri: 'https://graph.microsoft.com/v1.0/groups/@{parameters(''group-id'')}/members/$ref'
                    method: 'POST'
                    headers: {
                      'Content-Type': 'application/json'
                    }
                    body: {
                      '@odata.id': 'https://graph.microsoft.com/v1.0/directoryObjects/@{items(''For_each'')?[''additionalData'']?[''aadUserId'']}'
                    }
                    authentication: {
                      type: 'ManagedServiceIdentity'
                      identity: userAssignedIdentityId
                      audience: 'https://graph.microsoft.com'
                    }
                  }
                  runtimeConfiguration: {
                    contentTransfer: {
                      transferMode: 'Chunked'
                    }
                  }
                }
                Append_to_ActionsTaken: {
                  type: 'AppendToArrayVariable'
                  runAfter: {
                    Reset_a_password: ['Succeeded']
                  }
                  inputs: {
                    name: 'ActionsTaken'
                    value: 'User @{outputs(''Get_UPN'')} password has been successfully reset.'
                  }
                }
                Append_to_ActionsTaken2: {
                  type: 'AppendToArrayVariable'
                  runAfter: {
                    Revoke_sign_in_session: ['Succeeded']
                  }
                  inputs: {
                    name: 'ActionsTaken'
                    value: 'User @{outputs(''Get_UPN'')} active sign-in sessions have been revoked.'
                  }
                }
                'Send_an_email_(V2)': {
                  type: 'ApiConnection'
                  runAfter: {
                    Append_to_ActionsTaken2: ['Succeeded']
                  }
                  inputs: {
                    host: {
                      connection: {
                        name: "@parameters('$connections')['office365']['connectionId']"
                      }
                    }
                    method: 'post'
                    path: '/v2/Mail'
                    body: {
                      To: 'TMS.InfoSec.Incidents@contoso.com;midusabe@contoso.com'
                      Subject: 'Security Incident Response: Password Reset and Session Revocation for user @{outputs(''Get_UPN'')}'
                      Body: '<p>The following actions have been executed for Incident \"@{triggerBody()?[''object'']?[''properties'']?[''title'']}\" using playbook ${logicAppName} for UPN @{outputs(''Get_UPN'')}<br/><br/>Actions Taken:<br/>@{join(variables(''ActionsTaken''), ''<br/>- '')}</p>'
                      Importance: 'Normal'
                    }
                  }
                }
              }
            }
            'Add_comment_to_incident_(V3)': {
              type: 'ApiConnection'
              runAfter: {
                For_each: ['Succeeded']
              }
              inputs: {
                host: {
                  connection: {
                    name: "@parameters('$connections')['azuresentinel']['connectionId']"
                  }
                }
                method: 'post'
                path: '/Incidents/Comment'
                body: {
                  incidentArmId: '@triggerBody()?[''object'']?[''id'']'
                  message: '<strong>Actions Taken:</strong><br/>' +
                    '@{join(variables(''ActionsTaken''), ''<br/>- '')}'
                }
              }
            }
          }
          else: {
            actions: {
              'Send_an_email_-_Threshold_Exceeded': {
                type: 'ApiConnection'
                inputs: {
                  host: {
                    connection: {
                      name: "@parameters('$connections')['office365']['connectionId']"
                    }
                  }
                  method: 'post'
                  path: '/v2/Mail'
                  body: {
                    To: 'TMS.InfoSec.Incidents@contoso.com;midusabe@contoso.com'
                    Subject: 'Automation Skipped: Account Threshold Exceeded for ${logicAppName}'
                    Body: '<p>The playbook <strong>${logicAppName}</strong> was skipped because Incident \"@{triggerBody()?[''object'']?[''properties'']?[''title'']}\" has more than @{variables(''Threshold'')} linked accounts.</p>'
                    Importance: 'Normal'
                  }
                }
              }
            }
          }
        }
      }
      outputs: {}
    }
    parameters: {
      '$connections': {
        value: {
          azuresentinel: {
            id: sentinelConnectionId
            connectionName: 'azuresentinel-${logicAppName}'
            connectionId: sentinelConnectionExternalId
            connectionProperties: {
              authentication: {
                type: 'ManagedServiceIdentity'
              }
            }
          }
          office365: {
            id: office365ConnectionId
            connectionName: 'office365'
            connectionId: office365ConnectionExternalId
          }
        }
      }
    }
  }
}

output logicAppResourceId string = logicApp.id
