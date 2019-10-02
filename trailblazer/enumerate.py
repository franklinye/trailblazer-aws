import re

import boto3
from botocore.exceptions import ClientError, EndpointConnectionError

import csv
from collections import defaultdict

from trailblazer import log
from trailblazer.boto.util import botocore_config
from trailblazer.boto.service import get_boto_functions, get_service_call_params, \
									get_service_json_files, make_api_call, get_service_call_mutation
from trailblazer.boto.sts import get_assume_role_session

from datetime import datetime

def _fillvalue(shape):
    param = None
    # ignore some types
    if shape.type_name not in [ 'jsonvalue_string']:
        param = globals()['_fillvalue_%s' % shape.type_name](shape)
    log.debug('_fillvalue_{} with value {}'.format(shape.type_name, param))
    return param

def _fillvalue_blob(shape):
    return 'blob'

def _fillvalue_string(shape):
    param = 'x'
    if 'min' in shape.metadata:
        min_allowed = shape.metadata['min']
        param = ''.join('s' for i in range(min_allowed))
    elif 'enum' in shape.metadata:
        param = shape.metadata['enum'][0]
    return param

def _fillvalue_list(shape):
    param = list()
    if 'min' in shape.metadata:
        min_allowed = shape.metadata['min']
        for i in range(min_allowed):
            val = _fillvalue(shape.member)
            param.append(val)
    elif 'enum' in shape.metadata:
        param.append(shape.metadata['enum'][0])
    return param

def _fillvalue_map(shape):
    key = _fillvalue(shape.key_shape)
    param = dict()
    param[key] = _fillvalue(shape.value_shape)
    return param

def _fillvalue_integer(shape):
    min_allowed = 1
    if 'min' in shape.metadata:
        min_allowed = shape.metadata['min']
    return min_allowed

def _fillvalue_boolean(shape):
    return False

def _fillvalue_double(shape):
    min_allowed = 1.0
    if 'min' in shape.metadata:
        min_allowed = shape.metadata['min']
    return min_allowed

_fillvalue_float = _fillvalue_double

def _fillvalue_long(shape):
    min_allowed = 1
    if 'min' in shape.metadata:
        min_allowed = shape.metadata['min']
    return min_allowed

def _fillvalue_timestamp(shape):
    return datetime.now()

def _fillvalue_structure(shape):
    # Validate required fields.
    fillvalue_members = []
    for required_member in shape.metadata.get('required', []):
        fillvalue_members.append(required_member)
    params = dict()
    for param in fillvalue_members:
        val = _fillvalue(shape.members[param])
        log.debug('required: {} is filled with {}'.format(param, val))
        params[param] = val
    return params

def enumerate_services(config, services, dry_run=False):
    # read a CSV file for seen functions
    apis = defaultdict(list)
    with open('botocore_api_2_event_names.csv', 'rb') as csvfile:
        reader = csv.reader(csvfile)
        for row in reader:
            x = row[1].split('_')
            if len(x) > 1:
                # service_name without '-'
                apis[x[0]].append(row[1])
            else:
                # event_source as a service_name without '-'
                apis[row[0].replace('-', '')].append(row[1])

    # Create a boto3 session to use for enumeration
    session = boto3.Session()

    authorized_calls = []

    for service in services:

        if len(session.get_available_regions(service)) == 0:
            log.debug('Skipping {} - No regions exist for this service'.format(service))
            continue

        # Create a service client
        log.info('Creating {} client...'.format(service))

        # Grab a region to use for the calls.  This should be us-west-2
        region = session.get_available_regions(service)[-1]

        # Set the user-agent if specified in the config
        if config.get('user_agent', None):
            botocore_config.user_agent = config['user_agent']

        # Create a client with parameter validation off
        client = session.client(service, region_name=region, config=botocore_config)

        # Get the functions that you can call
        functions_list = get_boto_functions(client)

        # Get the service file
        service_file_json = get_service_json_files(config)

        # Get a list of params needed to make the serialization pass in botocore
        service_call_params = get_service_call_params(service_file_json[service])

        # Loop through all the functions and call them
        for function in functions_list:

            # The service_file_json doesn't have underscores in names so let's remove them
            function_key = function[0].replace('_','')

            ## Session Name Can only be 64 characters long
            srv_len = len(service)
            session_name = service.replace('-', '')
            if srv_len > 20:
                session_name = service[:19]
                srv_len = 20
            func_key_limit = 64 - srv_len - 1
            if len(function_key) > func_key_limit:
                session_name += '_' + function_key[:func_key_limit-1]
                log.info('Session Name {} is for {}:{}'.format(session_name, service, function_key))
            else:
                session_name += "_" + function_key

            # check session_name in the seen functions
            if session_name in apis[service.replace('-', '')]:
                log.info('found {}:{}, skipping'.format(service, session_name))
                continue

            # Set the session to the name of the API call we are making
            session = get_assume_role_session(
                account_number=config['account_number'],
                role=config['account_role'],
                session_id=session_name
            )

            new_client = session.client(service, region_name=region, config=botocore_config)
            new_functions_list = get_boto_functions(new_client)

            for new_func in new_functions_list:
                if new_func[0] == function[0]:

                    # We need to pull out the parameters needed in the requestUri, ex. /{Bucket}/{Key+} -> ['Bucket', 'Key']
                    params = re.findall('\{(.*?)\}', service_call_params.get(function_key, '/'))
                    params = [p.strip('+') for p in params]

                    try:
                        func_params = {}

                        for param in params:
                            # Set something because we have to
                            func_params[param] = 'testparameter'

                        log.info('Calling {}:{} with params {} in {}'.format(service, new_func[0], func_params, region))

                        # fill values for required members
                        operation_name = new_client._PY_TO_OP_NAME[new_func[0]]
                        operation_model = new_client._service_model.operation_model(operation_name)
                        input_shape = operation_model.input_shape
                        if service == 'sts' and operation_name == 'AssumeRole':
                            log.info('skipped sts:AssumeRole for required member')
                        elif input_shape.type_name == 'structure':
                            # find the required members
                            extra_params = _fillvalue(input_shape)
                            if extra_params:
                                func_params.update(extra_params)
                            else:
                                log.info('skipped this input_shape: {}'.format(input_shape))

                        if not dry_run:
                        	make_api_call(service, new_func, region, func_params)

                    except ClientError as e:
                        log.error('ClientError: {}:{} - {}'.format(service, new_func[0], e))
                    except EndpointConnectionError as e:
                        log.error('EndpointConnectionError: {}:{} - {}'.format(service, new_func[0], e))
                    except boto3.exceptions.S3UploadFailedError as e:
                        log.error('S3UploadFailedError: {}:{} - {}'.format(service, new_func[0], e))
                    except TypeError as e:
                        log.error('TypeError: {}:{} - {}'.format(service, new_func[0], e))
                    except KeyError as e:
                        log.error('Unknown Exception: {}:{} - {}'.format(service, new_func[0], e))
