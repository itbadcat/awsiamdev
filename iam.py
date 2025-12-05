import sys, argparse, logging, re
import colorlog
from inspect import signature, Parameter
from time import sleep
from boto3 import client as b3_client
from boto3.session import Session as B3Session
from botocore.exceptions import ClientError
from sshkeyboard import listen_keyboard, stop_listening

b3_session = None # Initialize global to None for initial run

def get_b3_client(service_id):
    """
    Creates a new boto3 client using most relevant credentials.
    :return: The new client instance.
    """
    logger.debug(f'Session is set to: {b3_session}')
    if b3_session is not None:
        return b3_session.client(service_id)
    else:
        return b3_client(service_id)

def get_new_logger():
    """
    Fetches a named logger with basic configuration in place.
    :param logging_level: The level at which log statements should be pushed to the output stream
    """
    handler = colorlog.StreamHandler()
    formatter = colorlog.ColoredFormatter('%(log_color)s%(levelname)-8s%(reset)s %(blue)s%(message)s', log_colors={ 'DEBUG': 'cyan', 'INFO': 'green', 'WARNING': 'orange', 'ERROR': 'red', 'CRITICAL': 'bold_red' })
    handler.setFormatter(formatter)
    logger = logging.getLogger(__name__) # Initialize new named logger
    logger.addHandler(handler)
    return logger

def print_help(print_numbers=False):
    """
    Prints the script help text.
    """
    print('Commands:')
    for i, v in enumerate(cmdmap):
        print(f'{str(i + 1) + ": " if print_numbers else ""}{v} - {cmdmap[v][1]}')

def count_req_args(function):
    """
    Count the number of required arguments to a given function.
    :param function: An object representing the function to be evaluated.
    :return: The number of required arguments for function.
    """
    sig = signature(function)
    req_args = 0
    for param in sig.parameters.values():
        if param.kind == Parameter.POSITIONAL_OR_KEYWORD and param.default == Parameter.empty: # Count positional or named arguments without a default as required
            req_args += 1
    return req_args

def process_args():
    """
    Process CLI arguments and raise errors if input is not correct.
    :return: A tuple containing the main action function for the script to perform and an argument, if needed.
    """
    parser = argparse.ArgumentParser()
    parser.add_argument('-v', action='store_true', help='Print debug messages during execution.')
    parser.add_argument('cmd', nargs='?', type=str.lower, help='Command to execute.')
    parser.add_argument('cmdarg', nargs='?', help='Argument for command.')
    args = parser.parse_args()
    logger.setLevel(logging.DEBUG if args.v else logging.INFO)
    logger.debug(f'Arguments parsed. Verbose mode is {'on' if args.v else 'off'}. Starting processing...')
    if args.cmd is None:
        logger.debug('Script executed with 0 arguments.')
        return (None, None)
    if args.cmd not in cmdmap:
        logger.error(f'{args.cmd} is not a valid command. Use one of: {", ".join(cmdmap)}')
        exit_clean(1) # Return code 1: invalid command supplied
    cmdfunc = cmdmap[args.cmd][0] # Index function object from cmdmap value tuple
    req_args = count_req_args(cmdfunc)
    logger.debug(f'Using command: {args.cmd}')
    if req_args > 0 and args.cmdarg is None:
        logger.error(f'Command {args.cmd} requires an argument.')
        exit_clean(2) # Return code 2: command requires an argument but none supplied
    return (cmdfunc, args.cmdarg)

def redact_acct_id(input_text, redact_output='<REDACTED>'):
    """
    Removes AWS account ID from a string object.
    :param input_text: The original text from which the account ID should be removed.
    :param redact_output: The replacement string to be substituted for input_text. Default: "<REDACTED>"
    :return: The redacted version of the original string.
    """
    return re.sub(r'(arn:aws:.*:)\d{12}', fr'\1{redact_output}', input_text) # Capture group not strictly necessary here but added to verify that no other text gets mangled

def list_users():
    """
    List defined IAM users in account.
    """
    try:
        iam_client = get_b3_client('iam')
        response = iam_client.list_users()
        print('+===+ Users +===+')
        for user in response['Users']:
            user_name = user['UserName']
            print(f'User Name: {user_name}')
            print(f'User ID: {user["UserId"]}')
            print(f'Path: {user["Path"]}')
            print(f'ARN: {redact_acct_id(user["Arn"])}')
            print(f'Created: {user["CreateDate"]}')
            grpresponse = iam_client.list_groups_for_user(UserName=user_name)
            if len(grpresponse) > 0:
                for grp in grpresponse['Groups']:
                    group_name = grp['GroupName']
                    print(f'Attached Group: {group_name}')
                    manpolresponse = iam_client.list_attached_group_policies(GroupName=group_name)
                    if len(manpolresponse['AttachedPolicies']) > 0:
                        print('  Attached Managed Policies:')
                        for manpol in manpolresponse['AttachedPolicies']:
                            print(f'    {manpol["PolicyName"]}')
                    inpolresponse = iam_client.list_group_policies(GroupName=group_name)
                    if len(inpolresponse['PolicyNames']) > 0:
                        print('  Attached Inline Policies:')
                        for inpol in inpolresponse['PolicyNames']:
                            print(f'    {inpol}')
            print('\n' + ('-' * 20) + '\n')
    except ClientError as e:
        logger.error(f'Unable to list users. Error code: {e.response["Error"]["Code"]}')

def list_roles():
    """
    List defined IAM roles in account.
    """
    try:
        iam_client = get_b3_client('iam')
        rolresponse = iam_client.list_roles()
        print('#===# Roles #===#')
        for role in rolresponse['Roles']:
            if not role['Path'].startswith('/aws-service-role/'): # Filter out service roles before outputting
                print(f'Role Name: {role["RoleName"]}')
                print(f'Role ID: {role["RoleId"]}')
                print(f'Path: {role["Path"]}')
                print(f'ARN: {redact_acct_id(role["Arn"])}')
                print(f'Created: {role["CreateDate"]}')
                print('\n' + ('-' * 20) + '\n')
    except ClientError as e:
        logger.error(f'Unable to list roles. Error code: {e.response["Error"]["Code"]}')

def list_alias():
    """
    List alias for current account.
    :return: The 'list' of aliases for the account.
    """
    logger.debug('Starting list_alias...')
    aliases = None
    try:
        logger.debug('Calling API for list_account_aliases...')
        iam_client = get_b3_client('iam')
        response = iam_client.list_account_aliases()
        aliases = response['AccountAliases']
        if len(aliases) > 0:
            logger.info(f'Account alias: {aliases[0]}') # There should only ever be one list item at most
        else:
            logger.info('No account alias found.')
    except ClientError as e:
        logger.error(f'Unable to list alias. Error code: {e.response["Error"]["Code"]}')
    finally:
        return aliases # This return statement is only needed because delete_alias uses the value. DO NOT DELETE.. AGAIN

def create_alias(alias):
    """
    Creates a new account alias if one does not exist or overwrites existing alias if one does.
    :param alias: The alias to create.
    """
    try:
        iam_client = get_b3_client('iam')
        iam_client.create_account_alias(AccountAlias=alias)
        logger.info(f'Created: {alias}')
    except ClientError as e:
        logger.error(f'Could not create alias {alias}. Error code: {e.response["Error"]["Code"]}')

def delete_alias():
    """
    Deletes the account alias.
    """
    logger.debug('Starting delete_alias...')
    alias = None
    try:
        # Temporarily suppress INFO level output printing
        logger.debug('Listing alias before deleting...')
        orig_log_level = logger.getEffectiveLevel()
        logger.setLevel(logging.WARNING)
        aliases = list_alias()
        logger.setLevel(orig_log_level)
        logger.debug(f'Alias list value: {aliases}')
        if aliases is not None and len(aliases) > 0:
            alias = aliases[0]
            iam_client = get_b3_client('iam')
            iam_client.delete_account_alias(AccountAlias=alias)
            logger.info(f'Deleted: {alias}')
        elif aliases is not None:
            logger.info('No account alias found.')
    except ClientError as e:
        logger.error(f'Could not remove alias {alias}. Error code: {e.response["Error"]["Code"]}')

def usage_summary():
    """
    Prints a summary of account usage.
    """
    try:
        iam_client = get_b3_client('iam')
        for k, v in iam_client.get_account_summary()['SummaryMap'].items(): # Dirty one-liner for demo use only. Look how concise it is!
            print(f'{k}: {v}')
    except ClientError as e:
        logger.error(f'Summary retrieval failed. Error code: {e.response["Error"]["Code"]}')

def assume_role(role_arn, session_name='S3HousinDemoSession', output_file='set_creds.sh'):
    """
    Acquires temporary credentials for the given role, creates global session instance, and creates a script to export credentials to a bash shell.
    :param role_arn: The ARN of the role to be assumed.
    :param session_name: A name by which the session will be referenced in logs.
    """
    global b3_session
    creds = None # Ensure that creds is never unbound
    try:
        sts_client = get_b3_client('sts')
        response = sts_client.assume_role(RoleArn=role_arn, RoleSessionName=session_name, DurationSeconds=3600) # Credentials valid for one hour
        creds = response['Credentials'] # Fetch credentials object from STS client response
        logger.debug('Creating session object for client generation...')
        b3_session = B3Session(aws_access_key_id=creds['AccessKeyId'], aws_secret_access_key=creds['SecretAccessKey'], aws_session_token=creds['SessionToken'], region_name='us-east-1')
        logger.info(f'Temporary credentials set for current script. To export to the shell, exit and source: {output_file}')
    except Exception as e:
        logger.error(f'Assume role failed. Error code: {e.response["Error"]["Code"]}')
    if creds is not None: # Check should be unnecessary, but just in case
        create_file(output_file, creds)

def create_file(file_path, creds):
    """
    Write temporary credentials to a file suitable for bash sourcing.
    :param file_path: The file which should be created.
    :param creds: Object containing the credential K/V pairs.
    """
    try:
        with open(file_path, 'w') as f:
            f.write(f'export AWS_ACCESS_KEY_ID={creds["AccessKeyId"]}\n')
            f.write(f'export AWS_SECRET_ACCESS_KEY={creds["SecretAccessKey"]}\n')
            f.write(f'export AWS_SESSION_TOKEN={creds["SessionToken"]}\n')
        logger.debug(f'File {file_path} created')
    except Exception as e:
        logger.error(f'Creating credential file failed: {e}')

def list_buckets():
    """
    List S3 buckets in the account.
    """
    try:
        s3_client = get_b3_client('s3')
        response = s3_client.list_buckets()
        print('#===# S3 Buckets #===#')
        for bucket in response['Buckets']:
            print(f'Bucket Name: {bucket["Name"]}')
            print(f'ARN: {bucket["BucketArn"]}')
            print(f'Created: {bucket["CreationDate"]}')
            print('\n' + ('-' * 20) + '\n')
    except ClientError as e:
        logger.error(f'Failed listing S3 buckets. Error code: {e.response["Error"]["Code"]}')

def list_analyzers():
    """
    Lists account-level IAM Access Analyzers.
    """
    try:
        aa_client = get_b3_client('accessanalyzer')
        response = aa_client.list_analyzers(type='ACCOUNT') # Account external access analyzers only
        if len(response['analyzers']) > 0:
            print('#===# IAM Access Analyzers #===#')
            for analyzer in response['analyzers']:
                show_analyzer(analyzer['name']) # Print details
                print('\n' + ('-' * 20) + '\n')
        else:
            logger.info('No access analyzers found.')
    except ClientError as e:
        logger.error(f'Failed listing analyzers. Error code: {e.response["Error"]["Code"]}')

def show_analyzer(name):
    """
    Retrieves information about an IAM Access Analyzer.
    :param name: The name of the analyzer to view.
    """
    try:
        aa_client = get_b3_client('accessanalyzer')
        response = aa_client.get_analyzer(analyzerName=name)
        analyzer = response['analyzer']
        print(f'Analyzer Name: {analyzer["name"]}')
        print(f'Analyzer Type: {analyzer["type"]}')
        print(f'ARN: {redact_acct_id(analyzer["arn"])}')
        print(f'Created: {analyzer["createdAt"]}')
        print(f'Status: {analyzer["status"]}')
        if 'statusReason' in analyzer: # Status reason not present for ACTIVE status
            print(f'Status Reason: {analyzer["statusReason"]}')
        print(f'Last Resource Analyzed: {analyzer["lastResourceAnalyzed"]}')
        if 'configuration' in analyzer: # Configuration data appears to not be present in external access analyzers
            print(f'Configuration: {analyzer["configuration"]}')
    except ClientError as e:
        logger.error(f'Failed displaying analyzer. Error code: {e.response["Error"]["Code"]}')

def list_analyzer_findings():
    """
    Lists findings from all external access analyzers.
    """
    try:
        aa_client = get_b3_client('accessanalyzer')
        la_response = aa_client.list_analyzers(type='ACCOUNT') # Account external access analyzers only
        print('#===# Analyzer Findings #===#')
        for analyzer in la_response['analyzers']:
            print(f'Analyzer Name: {analyzer["name"]}')
            lf_response = aa_client.list_findings(analyzerArn=analyzer['arn'])
            findings = lf_response['findings']
            if len(findings) > 0:
                print('  Findings:')
                for finding in findings:
                    print(f'    Finding ID: {finding["id"]}')
                    print(f'        Finding Status: {finding["status"]}')
                    print(f'        Resource: {finding["resource"]}')
                    print(f'        Resource Type: {finding["resourceType"]}')
                    print(f'        Resource Owner: {finding["resourceOwnerAccount"]}')
                    print(f'        Finding Sources: {", ".join([ source["type"] for source in finding["sources"] ])}')
                    print(f'        Public Access: {"YES" if finding["isPublic"] else "NO"}')
                    print(f'        Policy Principal: {finding["principal"]}')
                    print(f'        Policy Actions: {", ".join(finding["action"])}')
                    print(f'        Analyzed At: {finding["analyzedAt"]}')
                    print(f'        Updated At: {finding["updatedAt"]}')
            else:
                print('  No access analyzer findings.')
            print('\n' + ('-' * 20) + '\n')
    except ClientError as e:
        logger.error(f'Failed listing findings. Error code: {e.response["Error"]["Code"]}')

def get_valid_menu_selection(lower, upper, prompt_text='Please select an option (by number): '):
    """
    Collect an integer in the specified range from stdin.
    :param lower: The lower boundary of the acceptable range. Inclusive.
    :param upper: The upper boundary of the acceptable range. Inclusive.
    :param prompt_text: The text for the input prompt. Default: "Please select an option (by number): "
    """
    while True:
        try:
            selection = int(input(prompt_text))
            if selection not in range(lower, upper + 1):
                raise Exception('Number out of range.\n')
            print() # Print a single blank line
            break
        except Exception as e:
            logger.error(f'Invalid selection: {e}')
            continue
    return selection

def display_menu():
    """
    Display a text menu and allow option selection.
    :return: A tuple containing a function object based on the user's selection and, if required, an additional argument.
    """
    for i, v in enumerate(cmdmap):
        print(f'{i + 1}: {v} - {cmdmap[v][1]}')
    selection = get_valid_menu_selection(1, len(cmdmap))
    # Next line unnecessarily convoluted, FOR DEMO PURPOSES ONLY. Fun mental exercise starting now...
    selected_function = cmdmap[list(cmdmap.keys())[selection - 1]][0] # Access function object by selection as index value
    # Ok, it works. Now, let's never do it that way again. You're welcome
    req_args = count_req_args(selected_function)
    logger.debug(f'Required args for {selected_function.__name__}: {req_args}')
    addarg = input('Please enter an additional argument for this command: ') if req_args > 0 else None
    if addarg is not None:
        print() # Blank line for clean output
    return (selected_function, addarg)

def execute_main_action(main_action, arg):
    """
    Execute a function object with or without an argument.
    :param main_action: The function to execute
    :param arg: The command argument or None if no argument is needed
    """
    if arg is None:
        main_action()
    else:
        main_action(arg)

def exit_clean(exit_code=0):
    """
    Shut down the logging system and exit Python, returning exit_code to the OS.
    :param exit_code: The exit code to report up to the OS.
    """
    logger.debug(f'Shutting down logger and exiting with code {exit_code}...')
    logging.shutdown()
    sys.exit(exit_code)

# This need be below the function definitions!
# Commands should be listed in all lowercase because input is converted to lower
cmdmap = {
    'help': (print_help, 'Print this help text.'),
    'list-users': (list_users, 'Print the users in the account.'),
    'list-roles': (list_roles, 'Print the roles in the account.'),
    'list-alias': (list_alias, 'Print the current account alias.'),
    'create-alias': (create_alias, 'Set the account alias.'),
    'delete-alias': (delete_alias, 'Delete the account alias.'),
    'usage': (usage_summary, 'Print account usage summary.'),
    'assume-role': (assume_role, 'Assume a role limited to S3 read access.'),
    'list-buckets': (list_buckets, 'List S3 buckets.'),
    'list-analyzers': (list_analyzers, 'List IAM Access Analyzers.'),
    'list-findings': (list_analyzer_findings, 'List analyzer findings.'),
    'exit': (exit_clean, 'Exit this script.')
    }

if __name__ == '__main__':
    logger = get_new_logger() # Create named logger in scope of other functionality
    (main_action, arg) = process_args()
    logger.debug(f'CLI args processed as: {main_action} with command arg {arg}')
    interactive_mode = main_action is None
    while interactive_mode: # Fires if no arguments provided at CLI
        (main_action, arg) = display_menu()
        logger.debug(f'Executing selected menu option: {main_action} with arg {arg}')
        execute_main_action(main_action, arg)
        main_action, arg = None, None # Reset, just in case
        sleep(0.2) # Don't catch the Enter key release
        print('\nPress any key to continue...\n')
        listen_keyboard(on_release=lambda _: stop_listening()) # Lags a bit but works over SSH
    logger.debug(f'Executing direct command: {main_action} with arg {arg}')
    execute_main_action(main_action, arg)
    exit_clean()
