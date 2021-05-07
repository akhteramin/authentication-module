# Admin - Auth Moudle #
## Central Auth Feature Description. ##
Central Auth is an authentication module which will authenticate all registered applications in the system and facilitate users to access all applications with single credential. 			
## Application - Application Creation: ##
 Application can be registered in central Auth. Here internal application lists are maintained along with application description. After registration central auth will provide the application an Application ID which will a unique identifier for all other application.
## Application - Application Details Edit: ##
Application name and description can be edited.
## User - User Creation: ##
Users are registered here subscribing specific applications. That is while registering a user, he/she can be assigned to one/multiple applications. But these assignment will be done with respect to user type. Default password is also set by Auth Superuser.
## User - User Activation/Suspend: ##
An user can be suspended or activated from user list.
## Set Password of User: ## 
User password can be set by Auth Superuser from user list.
## Assign User to Application: ## 
User’s permission to specific app can be revoked but all application permission can;t be revoked. Thus when Auth Superadmin need to remove user from all application he/she can deactivate User from all applications.
## User Search:## 
From User list user can be searched based on Login  ID and Application ID

## Group - Group Creation: ##
Group is created under specific application. Group ID and description need to be added while creation.

## Group - Group Edit: ##
Group can be updated here.
## Group - Group Search: ##
From User list user can be searched based on these fields: Group  ID, Application Name
## Service - Service Creation: ##
Service is created under specific application. Service ID and description need to be added while creation.
## Service - Service Edit: ##
Service ID, description , category name can be updated here.
## Service - Service Search: ##
Service list can be searched based on these fields: Application Name, Service ID

## Service to Group Assignment - Service assignment to Group: ##
By selecting services, services can be assigned to specific group. As well as, services can also be revoked from group. This assigned service list is propagated to end user those who are subscribed to this group.
## Group to User Assignment - Group assign to User: ##
By selecting multiple groups, groups can be assigned to specific group. As well as, group permission can also be revoked from user. If user is assigned to multiple groups, service list from all groups are provided in permission list while logging in.

## Application Switching ##
All subscribed applications are shown here. From where user can easily switch from auth to another application.

## Application Authentication ##
Central Auth backend provides User-wise Permission List, store Service List, Authenticate each Service ID requested from different Module, validate Token, maintain token life expire time, define Email Dmain of User, and employ celery to manage concurrenct activity.


# Open API for priliminary setup #
http://127.0.0.1:8000/auth/api/v1/token/validation
Type: GET
Header
{
	token:”dgdfgdfg”
	service-id:”******”
}

http://127.0.0.1:8000/auth/api/v1/login/
Type: POST
BODY
{
	"loginID":"local@ipay.com.bd",
	"password":"1234567890",
	"appID": 10,
	"deviceID":"postman"
  }
Response Status: 400 ()

Get permission list
http://127.0.0.1:8000/auth/api/v1/permissions/
Type: GET
Header
{
	token:”eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2V4YW1wbGUuYXV0aDAuY29tLyIsImF1ZCI6Imh0dHBzOi8vYXBpLmV4YW1wbGUuY29tL2NhbGFuZGFyL3YxLyIsInN1YiI6InVzcl8xMjMiLCJpYXQiOjE0NTg3ODU3OTYsImV4cCI6MTQ1ODg3MjE5Nn0.CA7eaHjIHz5NxeIJoFK9krqaeZrPLwmMmgI_XiQiIkQ”
}


Change password:
http://127.0.0.1:8000/auth/api/v1/password/change/
Type: PUT
Body: {
            loginID: loginID,
            old_password: old_password,
            new_password: new_password,
            appID: appID
          }
Header: token

