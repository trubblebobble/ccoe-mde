import base64
import datetime
import hashlib
import hmac
import json
import logging
import msal
import os
import requests

import azure.functions as func
import azure.durable_functions as df
import azure.durable_functions.models.utils.entity_utils as utils

from azure.core.exceptions import ResourceExistsError
from azure.data.tables import TableServiceClient
from azure.storage.blob import BlobServiceClient, BlobClient, ContainerClient
from email.utils import formatdate

# URI end points required
identity_authority = 'https://login.microsoftonline.com'

api_resource = 'https://graph.microsoft.com'
api_resource_alerts_endpoint = f'{api_resource}/v1.0/security/alerts_V2'
api_resource_schema = f'{api_resource}/v1.0/$metadata#security/alerts_v2'

# Logging options
send_heartbeat = bool(os.environ['FunctionConfigSend_heartbeat'])

log_prefix = 'PyLA[t]'

use_last_saved_time = os.environ['FunctionConfigUse_last_saved_time']

# Main function called by timer uses stateful access token to preserve token values between each function invocation
async def main(mytimer: func.TimerRequest, loganalyticsrefreshtoken: str) -> None:

    startTime = datetime.datetime.utcnow()

    # Read environment variables into local vars for convenience:
    mde_tenant_id = os.environ['FunctionConfigMDETenantId']
    mde_client_app_id = os.environ['FunctionConfigMDEClientAppId']

    # Destination Log Analytics Workspace params:
    log_analytics_key = os.environ['FunctionConfigLogAnalyticsKey']
    log_analytics_workspace_id = os.environ['FunctionConfigLogAnalyticsWorkspaceId']
    log_analytics_table = os.environ['FunctionConfigLogAnalyticsTableName']

    # Note this has to be after settings are loaded as some logging targets require config settings to be loaded first
    do_logging('info', 5, f'Starting timer-Python-LogAnalytics')

    if mytimer.past_due:
        do_logging('info', 5, 'The timer is past due!')

    # Set up MSAL context for authenticating with Defender API
    authorityURI = f'{identity_authority}/{mde_tenant_id}'

    scopes = [f'{api_resource}/.default']
    app = msal.PublicClientApplication(client_id=mde_client_app_id, authority=authorityURI)

    # Set entity context to retrieve the refresh token from the last invocation
    do_logging('info', 4, 'Retrieving Entity State')
    client = df.DurableOrchestrationClient(loganalyticsrefreshtoken)
    entity_id = utils.EntityId('entity-Python-LogAnalytics', 'PyLARefToken')
    client_entity_state = await client.read_entity_state(entity_id)

    # Only log this while debugging as state information could contain sensitive information
    do_logging('info', 1, f'Entity State from last Invocation: {client_entity_state.entity_state}')

    # Declare access_token first in case of manual login
    access_token = None
    if client_entity_state.entity_state:
        refresh_token = client_entity_state.entity_state.replace('"', '')
        do_logging('info', 1, f'Refresh token found in Entity State')

    else:
        refresh_token = 'No Token Stored'

    # Use refresh token to re-authenticate without needing device code
    if refresh_token != 'No Token Stored':
        do_logging('info', 3, 'Refresh token present in Entity, re-authenticating with token...')
        try:
            tokens = app.acquire_token_by_refresh_token(refresh_token=refresh_token, scopes=scopes)
            access_token = tokens['access_token']
            refresh_token = tokens['refresh_token']
            do_logging('info', 1, f'Access and Refresh tokens acquired from previous refresh token')

        except:
            refresh_token = 'No Token Stored'
            do_logging('exception', 3, 'Refresh token was not valid, resetting.')

    # Not making this an else because if the refresh token is not valid, manual login is required anyway.
    if refresh_token == 'No Token Stored':
        do_logging('info', 3, 'No refresh token found, manual login required.')

        # The manual login step is the most finnicky- it requires the user to dive into the function logs
        #  to retrieve the device code, unless that log is established as a function alert.
        tokens = do_manual_login(app, scopes)

        if not tokens:
            # We can't continue running if we don't have tokens. Generate a heartbeat notifying of the error and exit.
            create_heartbeat('Unable to Authenticate to Defender API due to failed manual login.')
            do_logging('exception', 1, f'Unable to Authenticate to Defender API due to failed manual login.')
            return

        access_token = tokens['access_token']
        refresh_token = tokens['refresh_token']
        do_logging('info', 1, f'Access and Refresh tokens acquired from manual login')

    # Push new refresh token to orchestrator for next invocation.
    do_logging('info', 4, f'Authentication successful. Saving Refresh token for next execution.')
    instance_id = await client.start_new('orchestrator-Python-LogAnalytics', None, refresh_token)

    do_logging('info', 1, f'Orchestrator ID: {instance_id}')

    # Retrieve new alerts from Defender API with the supplied query and access token
    query = get_query_filter_time_string(startTime, mytimer.past_due)
    if len(query) > 0:
        query = f'$filter={query}'

    do_logging('info', 3, 'Starting retrieval of new alerts...')

    # Get the alerts
    alerts = do_get_new_alerts(access_token, query)

    # Alerts are in an odata object as a collection inside the "values" attribute, so extract them into a new empty map:
    records = []
    records = alerts['value']

    do_logging('info', 3, f'Retrieval complete, {len(records)} alerts for transfer.')

    # If we get more than one record back, we need to send them one at a time to the
    # Azure Sentinel instance otherwise we'll only see one alert with a batch of logs.
    successfuls = 0
    for i, record in enumerate(records):
        do_logging('info', 2, f'Processing record {i+1} of {len(records)}')

        # Process the raw json object to surface some of the child properties for easier processing in Sentinel
        body = create_alert_body(record)

        response = None
        try:
            response = do_post_log_analytics(log_analytics_workspace_id, body, log_analytics_key, log_analytics_table)
            do_logging('info', 2, f'Request sent, response code: {response.status_code}')

            successfuls += 1
        except Exception as e:
            do_logging('exception', 5, f'Unhandled Requests Exception: {str(e)}')

        if not response == None and not response.status_code == requests.codes.ok:
            do_logging('error', 5, f'Bad response status code found: {response.status_code}. Additional info:\n{response.text}')

    # If all alerts were pushed successfully we can update the query end time that has been processed up to:
    if successfuls==len(records) and len(query_end_time_str) >0 and use_last_saved_time:
        save_cached_query_end_time(query_end_time_str)

    # Creating a custom heartbeat message allows us to write a lightweight parser to check
    # for health issues in the script.
    heartbeatMessage = f'Processed {successfuls} out of {len(records)} new alerts.'
    create_heartbeat(heartbeatMessage)

    do_logging('info', 2, f'Processed {successfuls} out of {len(records)} new alerts.')
    do_logging('info', 3, 'Python timer trigger function completed')


def create_alert_body(record):
    # Python to search and if exists move keys and values defined from
    do_logging('info', 1, 'Creating alert body')

    # Define the keys to search for
    global keys_to_find
    keys_to_find = ['domainName','accountName','ipAddress']

    # Define a dictionary to hold the values of the keys
    global values_to_copy
    values_to_copy = {}

    # Call the search_for_keys function to find the values of the keys
    search_for_keys(record)

    # Add the key-value pairs to the root of the JSON data
    for key, value in values_to_copy.items():
        record[key] = value

    do_logging('info', 1, f'Created alert body: \n{record}')
    return record


def do_manual_login(app, scopes):

    do_logging('info', 3, f'Interactive Logon started.')

    # MSAL
    device_flow = app.initiate_device_flow(scopes=scopes)

    # Output the built-in message giving user the url and device code to log in with
    do_logging('info', 5, device_flow["message"])

    # This statement should hang until logon process completes then resume the function normally
    try:
        # MSAL
        tokens = app.acquire_token_by_device_flow(device_flow)
        do_logging('info', 3, 'Interactive logon complete. Initial access token and refresh token acquired.')

    except msal.exception.MsalServiceException:
        do_logging('exception', 5, 'Error Authenticating due to interactive login code expiry.')
        tokens = {}

    return tokens


def get_query_filter_time_string(startTime, timer_past_due):
    # The timer runs every 5 minutes, so we need to get the previous 5 minute segment to build
    # our query off. To do this we add 1 second to account for early invocation, then subtract
    # 5 minutes and do a floor and ceiling equation to determine the proper no-overlap window.
    # queryDepth should be == timer interval, and is set in the settings.conf

    queryDepth = int(os.environ['FunctionConfigQueryDepth'])

    timeSlice = datetime.timedelta(minutes=queryDepth)
    queryTime = startTime - timeSlice + datetime.timedelta(seconds=1)

    # If function was not running or some other event caused it not to complete successfully, 
    # check if we should use the last successful run time to determine the start of next run:
    query_start_time_str = ''
    if timer_past_due and use_last_saved_time:
        # get cached end time
        query_start_time_str = get_cached_query_start_time()
        do_logging('info', 2, f'Using cached Query End Time to get correct Start Time: {query_start_time_str}')

    # If not using last saved time, or no saved time was found:
    if len(query_start_time_str) == 0:
        query_start_time = queryTime - datetime.timedelta(minutes=queryTime.minute % queryDepth)
        query_start_time_str = datetime.datetime.strftime(query_start_time, '%Y-%m-%dT%H:%M:00.000Z')

    # End time is based on current time:
    query_end_time = (queryTime + (datetime.datetime.min - queryTime) % timeSlice) - datetime.timedelta(seconds=1)
    global query_end_time_str
    query_end_time_str = datetime.datetime.strftime(query_end_time, '%Y-%m-%dT%H:%M:%S.999Z')

    query = f'createdDateTime+ge+{query_start_time_str}+and+createdDateTime+le+{query_end_time_str}'

    do_logging('info', 2, f'Query time filter set: {query}')

    # for testing:
    # query='createdDateTime+ge+2023-03-02T15:51:54.8218609Z+and+createdDateTime+le+2023-03-05T17:53:54.8218609Z'

    return query


def get_cached_query_start_time():
    # Get last query end time and add one second to it:
    end_time_str = get_cached_query_end_time()
    
    do_logging('info', 1, f'Last Saved query end time: {end_time_str}')

    # convert datetime string to datetime object - remove timezone suffix but include milliseconds
    end_time_dt = datetime.datetime.strptime(end_time_str[:-1], "%Y-%m-%dT%H:%M:%S.%f")

    # add one second to datetime object to account for having removed a second when determining the end time:
    end_time_dt += datetime.timedelta(seconds=1)

    # start time is then zero seconds past this corrected end time
    start_time_str = datetime.datetime.strftime(end_time_dt, '%Y-%m-%dT%H:%M:00.000Z')

    do_logging('info', 2, f'New query start time: {start_time_str}')

    return start_time_str


def get_cached_query_end_time():
    # Get name of Azure Table and then get table client used to interact with it
    table_name = os.environ['FunctionConfigStorageTable']
    table_client = get_table_client(table_name)

    entity = table_client.get_entity(partition_key='CachedValue', row_key='QueryEndTime')

    do_logging('info', 2, f'Read cached query end time: {entity["end_time"]}')

    return entity["end_time"]


def save_cached_query_end_time(end_time):
    # Get name of Azure Table and then get table client used to interact with it
    table_name = os.environ['FunctionConfigStorageTable']
    table_client = get_table_client(table_name)

    # Insert or update the cached time
    my_entity = {
        'PartitionKey': 'CachedValue',
        'RowKey': 'QueryEndTime',
        'end_time': end_time
    }
    try:
        entity = table_client.create_entity(entity=my_entity)
    except ResourceExistsError:
        entity = table_client.update_entity(entity=my_entity)
    
    do_logging('info', 2, f'Saved Query End Time for next run: {end_time}')


def get_table_client(table_name):
    # Get the Azure Storage table client used to then interact with the table
    connection_string = os.environ['AzureWebJobsStorage']
    table_service_client = TableServiceClient.from_connection_string(conn_str=connection_string)
    table_client = table_service_client.get_table_client(table_name=table_name)

    do_logging('info', 2, f'Table client obtained for table: {table_name}')

    return table_client


def do_post_log_analytics(log_analytics_workspace_id, data, log_analytics_key, log_analytics_table):
    do_logging('info', 3, 'Building Log Analytics Post request...')

    apiVersion = '2016-04-01'
    contentType = 'application/json'
    api_resource = '/api/logs'

    logAnalyticsURI = f'https://{log_analytics_workspace_id}.ods.opinsights.azure.com{api_resource}?api-version={apiVersion}'

    # Using formatdate instead of datetime as it's cleaner than using strftime
    requestTime = formatdate(timeval=None, localtime=False, usegmt=True)
    contentLength = len(json.dumps(data))

    # Get the authorization signature headers with which to post to log analytics api:
    signature = build_signature(requestTime, 'POST', contentLength, contentType, api_resource, log_analytics_key, log_analytics_workspace_id)

    headers = {
        'Authorization': signature,
        'Log-Type': log_analytics_table,
        'x-ms-date': requestTime,
        'time-generated-field': 'DateValue'
    }

    do_logging('info', 2, f'Built Request for data: {data}')

    try:
        response = requests.post(logAnalyticsURI, json=data, headers=headers)

    except Exception as e:
        do_logging('exception', 5, f'Unhandled exception caught at requests stage: {str(e)}')

    return response


def build_signature(date, method, contentLength, contentType, api_resource, log_analytics_key, log_analytics_workspace_id):
    do_logging('info', 1, 'Building signature...')

    # Header creation logic provided by Jane Rowe
    xHeaders = f'x-ms-date:{date}'
    strToHash = '\n'.join([method, str(contentLength), contentType, xHeaders, api_resource])
    byteHash = bytes(strToHash, 'UTF-8')
    keyBytes = base64.b64decode(log_analytics_key)
    sha256 = hmac.new(keyBytes, byteHash, digestmod=hashlib.sha256)
    calcHash = sha256.digest()
    # b64encode returns a byte string, we need to decode to UTF-8.
    encodedHash = base64.b64encode(calcHash).decode()
    authorization = f'SharedKey {log_analytics_workspace_id}:{encodedHash}'

    do_logging('info', 1, 'Generated signature.')

    return authorization


def do_get_new_alerts(access_token, query):
    do_logging('info', 3, 'Retrieving alerts from Defender API...')

    headers = {
        "Authorization": "Bearer " + access_token,
        "Content-Type": "application/json"
    }
    # Set up api endpoint to get alerts from, and add filter query
    alertsURI = f'{api_resource_alerts_endpoint}?{query}'

    do_logging('info', 1, f'alertsURI: {alertsURI}')

    try:
        response = requests.get(alertsURI, headers=headers)
    except:
        do_logging('exception', 5, 'Unhandled exception caught while getting alerts.')

    alertsJson = {}

    do_logging('info', 1, f'Read new alerts: response.status_code: {response.status_code}')

    if response.status_code == requests.codes.ok:
        alertsJson = response.json()

    return alertsJson


def get_settings():
    # Get settings from file - may be considered legacy now as settings read from App Settings
    do_logging('info', 1, f'{log_prefix}: Get configuration settings from file')
    settings_dict = {}
    try:
        with open('settings.conf', 'r') as settings_file:
            setting_lines = settings_file.readlines()
        for line in setting_lines:
            # Allow for comment lines in the config file
            if not line.startswith('#'):
                key, val = line.split('::- ')
                settings_dict[key] = val.strip()
    except Exception as e:
        logging.exception(f'Unhandled file reading exception: {str(e)}')

    return settings_dict


def create_heartbeat(message, log_analytics_table='Heartbeat'):
    # Creating the custom heartbeat with minimal data to allow for health checks in Sentinel.

    # Read directly from variables to save needlessly passing parameter values through functions:
    log_analytics_key = os.environ['FunctionConfigLogAnalyticsKey']
    log_analytics_workspace_id = os.environ['FunctionConfigLogAnalyticsWorkspaceId']

    do_logging('info', 1, f'Creating {log_analytics_table} message...')

    heartbeatTime = str(datetime.datetime.utcnow()).replace(' ', 'T')
    jsonDict = {
        '@odata.context': f'{api_resource_schema}',
        'value': [
            {
                'title': f'Python LogAnalytics {log_analytics_table}',
                'severity': 'Low',
                'status': 'Resolved',
                'alertCreationTime': heartbeatTime,
                'firstEventTime': heartbeatTime,
                'lastEventTime': heartbeatTime,
                'resolvedTime': heartbeatTime,
                'description': message
            }
        ]
    }
    if send_heartbeat == True:
        try:
            response = do_post_log_analytics(log_analytics_workspace_id, jsonDict, log_analytics_key, log_analytics_table)
        except:
            do_logging('exception', 5, 'Failed to send heartbeat.')

        if not response.status_code == requests.codes.ok:
            do_logging('error', 5, f'Bad response status code found: {response.status_code}. Additional info:\n{response.text}')
    else:
        do_logging('info', 3, f'{log_analytics_table} Heartbeat message: {jsonDict}')


def upload_blob(blobData):
    # Temporary function to upload a blob, e.g. in place of sending logging to the Monitor service, which is subject to delays
    connection_string = os.environ['AzureWebJobsStorage']
    blob_service_client = BlobServiceClient.from_connection_string(connection_string)

    container_name = os.environ['FunctionConfigStorageContainer']
    container_client = blob_service_client.get_container_client(container_name)

    blob_name = f"blobData-{str(datetime.datetime.utcnow()).replace(' ', 'T')}.json"
    blob_client = container_client.get_blob_client(blob_name)

    blob_client.upload_blob(blobData, overwrite=True)

    do_logging('info', 1, f'Uploaded Azure Storage blob')



def do_logging(logging_class, logging_level, msg):
    # output logging to specified output - useful in debugging as blob output is more responsive than logging entries in Monitor
    
    # logging_type: logging = native function logging; blob = export to Azure blob; print = print to console
    logging_type = os.environ['FunctionConfigLoggingType']

    # each logging command is given a logging level 1-5 but only levels equal or higher to configured threshold are actually logged
    config_logging_level = int(os.environ['FunctionConfigLoggingLevel'])

    if logging_level >= config_logging_level:
        if logging_type == 'blob':
            msg = f'{datetime.datetime.utcnow()}: {log_prefix}: {msg}'
            upload_blob(msg)

        elif logging_type == 'print':
            msg = f'{datetime.datetime.utcnow()}: {log_prefix}: {msg}'
            print(msg)

        else:
            msg = f'{log_prefix}: {msg}'
            if logging_class == 'debug':
                logging.debug(msg)
            elif logging_class == 'error':
                logging.error(msg)
            elif logging_class == 'exception':
                logging.exception(msg)
            elif logging_class == 'warn':
                logging.warn(msg)
            else:
                logging.info(msg)


def search_for_keys(data):
    # Function to search for the keys in the JSON data
    do_logging('info', 1, f'Searching for key in supplied map')
    
    # Check if the keys exist in the current level of the JSON data
    for key in keys_to_find:
        if key in data:
            values_to_copy[key] = data[key]
    
    # Recursively search nested arrays and objects
    for key, value in data.items():
        if isinstance(value, dict):
            search_for_keys(value)
        elif isinstance(value, list):
            for item in value:
                if isinstance(item, dict):
                    search_for_keys(item)
