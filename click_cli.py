import sys
import click
import requests
from eth_account.messages import defunct_hash_message, encode_defunct
from eth_account.account import Account
import getpass
import json
import os
import pwd
from eth_utils import to_normalized_address
from solidity_parser import parser
from utils.EVContractUtils import extract_abi, ABIParser

CONTEXT_SETTINGS = dict(
    help_option_names=['-h', '--help']
)

CLEAN_SLATE_SETTINGS = {
  "PRIVATEKEY": None,
  "INTERNAL_API_ENDPOINT": "https://beta.ethvigil.com/api" if not "ETHVIGIL_API_ENDPOINT" in os.environ else os.environ['ETHVIGIL_API_ENDPOINT'],
  "REST_API_ENDPOINT": None,
  "ETHVIGIL_USER_ADDRESS": "",
  "ETHVIGIL_API_KEY": ""

}

if "ETHVIGIL_CLI_TESTMODE" in os.environ:
    settings_json_loc = os.getcwd() + '/.ethvigil/settings.json'
    settings_json_parent_dir = os.getcwd() + '/.ethvigil'
else:
    settings_json_loc = pwd.getpwuid(os.getuid()).pw_dir + '/.ethvigil/settings.json'
    settings_json_parent_dir = pwd.getpwuid(os.getuid()).pw_dir + '/.ethvigil'

@click.group(context_settings=CONTEXT_SETTINGS)
@click.pass_context
def cli(ctx):
    try:
        with open(settings_json_loc, 'r') as f:
            s = json.load(f)
    except:
        # settings file does not exist, copy over settings.null.json
        try:
            os.stat(settings_json_parent_dir)
        except:
            os.mkdir(settings_json_parent_dir)
        # create settings file from empty JSON file
        with open(settings_json_loc, 'w') as f2:
            json.dump(obj=CLEAN_SLATE_SETTINGS, fp=f2)
        s = CLEAN_SLATE_SETTINGS
    finally:
        ctx.obj = {'settings': s}


def ev_login(internal_api_endpoint, private_key, verbose=False):
    msg = "Trying to login"
    message_hash = encode_defunct(text=msg)
    signed_msg = Account.sign_message(message_hash, private_key)
    # --ETHVIGIL API CALL---
    headers = {'accept': 'application/json', 'Content-Type': 'application/json'}
    r = requests.post(internal_api_endpoint + '/login',
                      json={'msg': msg, 'sig': signed_msg.signature.hex()}, headers=headers)
    if verbose:
        click.echo(r.text)
    if r.status_code == requests.codes.ok:
        r = r.json()
        return r['data']
    else:
        return None


def ev_signup(internal_api_endpoint, invite_code, private_key, verbose):
    msg = "Trying to signup"
    message_hash = encode_defunct(text=msg)
    signed_msg = Account.sign_message(message_hash, private_key)
    # --ETHVIGIL API CALL to /signup---
    try:
        r = requests.post(internal_api_endpoint + '/signup', json={
            'msg': msg, 'sig': signed_msg.signature.hex(), 'code': invite_code
        })
    except:
        return False
    else:
        if verbose:
            print(r.url)
            print(r.text)
        if r.status_code == requests.codes.ok:
            return r.json()
        else:
            return False


def fill_rest_api_endpoint(new_endpoint):
    with open(settings_json_loc, 'w') as f:
        j = json.load(f)
        if 'REST_API_ENDPOINT' not in j or j['REST_API_ENDPOINT'] != new_endpoint:
            j['REST_API_ENDPOINT'] = new_endpoint
            json.dump(j, f)
            click.echo('Set REST API endpoint for contract calls in settings.json')
            click.echo(new_endpoint)

@cli.command()
@click.option('--verbose', 'verbose', default=False, type=bool)
@click.pass_obj
def init(ctx_obj, verbose):
    if not ctx_obj['settings']['PRIVATEKEY']:
        invite_code = click.prompt('Enter your invite code', hide_input=True)
        new_account = Account.create('RANDOM ENTROPY WILL SUCK YOUR SOUL')
        signup_status = ev_signup(ctx_obj['settings']['INTERNAL_API_ENDPOINT'], invite_code, new_account.key.hex(), verbose)
        if not signup_status:
            click.echo('Signup failed')
            return
        else:
            ctx_obj['settings']['PRIVATEKEY'] = new_account.key.hex()
            ctx_obj['settings']['ETHVIGIL_USER_ADDRESS'] = new_account.address

            with open(settings_json_loc, 'w') as f:
                json.dump(ctx_obj['settings'], f)
            click.echo('Sign up succeeded...')
            click.echo('Logging in with your credentials...')
            login_data = ev_login(ctx_obj['settings']['INTERNAL_API_ENDPOINT'], new_account.key.hex(), verbose)
            if len(login_data.keys()) > 0:
                ctx_obj['settings']['ETHVIGIL_API_KEY'] = login_data['key']
                ctx_obj['settings']['READ_API_KEY'] = login_data['readKey']
                ctx_obj['settings']['REST_API_ENDPOINT'] = login_data['api_prefix']

                click.echo('You have signed up and logged in successfully to EthVigil Alpha')
                if verbose:
                    click.echo('---YOU MIGHT WANT TO COPY THESE DETAILS TO A SEPARATE FILE---')
                    click.echo('===Private key (that signs messages to interact with EthVigil APIs===')
                    click.echo(ctx_obj['settings']['PRIVATEKEY'])
                    click.echo('===ETHEREUM hexadecimal address corresponding to above private key===')
                    click.echo(ctx_obj['settings']['ETHVIGIL_USER_ADDRESS'])
                with open(settings_json_loc, 'w') as f:
                    json.dump(ctx_obj['settings'], f)
                if verbose:
                    click.echo('Wrote context object to settings location')
                    click.echo(settings_json_loc)
                    click.echo('Context object')
                    click.echo(ctx_obj)
                sys.exit(0)
            else:
                click.echo('Login failed with credentials. Run `ev-cli reset`.')
                sys.exit(2)
    else:
        click.echo("A registered private key exists for this ev-cli installation. Run ev-cli reset if you wish"
                   " to do a fresh install")
        sys.exit(1)


@cli.command()
@click.pass_obj
def reset(ctx_obj):
    if click.confirm('Do you want to reset the current EthVigil CLI configuration and state?'):
        try:
            with open(settings_json_loc, 'w') as f2:
                json.dump(CLEAN_SLATE_SETTINGS, f2)
        finally:
            click.echo('EthVigil CLI tool has been reset. Run `ev-cli init` to reconfigure.')


@cli.command()
@click.option('--verbose', 'verbose_flag', type=bool, default=False)
@click.pass_obj
def login(ctx_obj, verbose_flag):
    if not ctx_obj['settings']['PRIVATEKEY']:
        click.echo('No Private Key configured in settings.json to interact with EthVigil APIs. Run `ev-cli init`.')
        return
    click.echo(ctx_obj)
    account_data = ev_login(internal_api_endpoint=ctx_obj['settings']['INTERNAL_API_ENDPOINT'],
                            private_key=ctx_obj['settings']['PRIVATEKEY'],
                            verbose=verbose_flag)
    fill_rest_api_endpoint(account_data['api_prefix'])


@cli.command()
@click.option('--raw', 'raw', type=bool, default=False)
@click.pass_obj
def accountinfo(ctx_obj, raw):
    a_data = ev_login(internal_api_endpoint=ctx_obj['settings']['INTERNAL_API_ENDPOINT'],
                      private_key=ctx_obj['settings']['PRIVATEKEY'],
                      verbose=False)
    if not raw:
        for k in a_data:
            d = a_data[k]
            if k == 'contracts':
                click.echo(f'Contracts deployed/verified:\n=============')
                for _k in d:
                    del(_k['appId'])
                    click.echo(f'Name: {_k["name"]}')
                    click.echo(f'Address: {_k["address"]}')
                    click.echo('--------------------')
            elif k == 'key':
                click.echo(f'EthVigil API key: \t {d}\n=============\n')
            elif k == 'api_prefix':
                click.echo(f'REST API prefix: \t {d}\n=============\n')
            elif k == 'hooks':
                click.echo(f'Registered integrations/hooks: \t {d}\n=============\n')
            elif k == 'hook_events':
                click.echo(f'Contracts events fired to registered hooks: \t {d}\n=============\n')
    else:
        click.echo(a_data)


@cli.command()
@click.pass_obj
def dumpsettings(ctx_obj):
    click.echo(json.dumps(ctx_obj['settings']))


@cli.command()
@click.argument('importfile', type=click.File('r'))
@click.option('--verbose', 'verbose', type=bool, default=False)
def importsettings(importfile, verbose):
    settings = json.load(importfile)
    if verbose:
        click.echo('Got settings from input file: ')
        click.echo(settings)
    # write into settings.json
    with open(pwd.getpwuid(os.getuid()).pw_dir+'/.ethvigil/settings.json', 'w') as f:
        json.dump(settings, f)

@cli.command()
@click.option('--contractName', 'contract_name', required=True,
              help='name of the contract to be deployed. For eg. FixedSupplyToken')
@click.option('--constructorInputs', 'inputs',
              help='constructor input values as a JSON list. OPTIONAL. If you do not specify, you shall be prompted for the same. '
                   'Eg: \'["abced", "0x008604d4997a15a77f00CA37aA9f6A376E129DC5"]\' '
                   'for constructor inputs of type (string, address). '
                   'Can be left empty if there are no inputs accepted by the constructor')
@click.option('--verbose', 'verbose', type=bool, default=False)
@click.argument('contract', type=click.Path(exists=True, dir_okay=False))
@click.pass_obj
def deploy(ctx_obj, contract_name, inputs, verbose, contract):
    """
    Deploys a smart contract from the solidity source code specified

    CONTRACT: path to the solidity file

    Usage example: ev-cli deploy contracts/Microblog.sol --contractName=Microblog --constructorInputs='JSON representation of the constructor arguments in an array'
    """
    constructor_input_prompt = False
    if verbose:
        click.echo('Got constructor inputs: ')
        click.echo(inputs)
    if inputs:
        c_inputs = json.loads(inputs)
    else:
        constructor_input_prompt = True
        c_inputs = list()  # an empty list
    sources = dict()
    if contract[0] == '~':
        contract_full_path = os.path.expanduser(contract)
    else:
        contract_full_path = contract
    resident_directory = ''.join(map(lambda x: x+'/', contract_full_path.split('/')[:-1]))
    contract_file_name = contract_full_path.split('/')[-1]
    contract_file_obj = open(file=contract_full_path)

    main_contract_src = ''
    while True:
        chunk = contract_file_obj.read(1024)
        if not chunk:
            break
        main_contract_src += chunk
    sources[f'ev-cli/{contract_file_name}'] = {'content': main_contract_src}
    # loop through imports and add them to sources
    source_unit = parser.parse(main_contract_src)
    source_unit_obj = parser.objectify(source_unit)

    for each in source_unit_obj.imports:
        import_location = each['path'].replace("'", "")
        # TODO: follow specified relative paths and import such files too
        if import_location[:2] != './':
            click.echo(f'You can only import files from within the same directory as of now', err=True)
            return
        # otherwise read the file into the contents mapping
        full_path = resident_directory + import_location[2:]
        imported_contract_obj = open(full_path, 'r')
        contract_src = ''
        while True:
            chunk = imported_contract_obj.read(1024)
            if not chunk:
                break
            contract_src += chunk
        sources[f'ev-cli/{import_location[2:]}'] = {'content': contract_src}

    if len(c_inputs) == 0 and constructor_input_prompt:
        abi_json = extract_abi(ctx_obj['settings'], {'sources': sources, 'sourceFile': f'ev-cli/{contract_file_name}'})
        abp = ABIParser(abi_json=abi_json)
        abp.load_abi()
        if len(abp.constructor_params()) > 0:
            click.echo('Enter constructor inputs...')
            for idx, each_param in enumerate(abp.constructor_params()):
                param_type = abp._constructor_mapping["constructor"]["input_types"][idx]
                param_type_cat = abp.type_category(param_type)
                arg = click.prompt(f'{each_param}({param_type})')
                if param_type_cat == 'integer':
                    arg = int(arg)
                elif param_type_cat == 'array':
                    # check if it can be deserialized into a python dict
                    try:
                        arg_dict = json.loads(arg)
                    except json.JSONDecodeError:
                        click.echo(f'Parameter {each_param} of type {param_type} '
                                   f'should be correctly passed as a JSON array', err=True)
                        sys.exit(1)
                c_inputs.append(arg)
    msg = "Trying to deploy"
    message_hash = encode_defunct(text=msg)
    # deploy from alpha account
    signed_msg = Account.sign_message(message_hash, ctx_obj['settings']['PRIVATEKEY'])
    deploy_json = {
        'msg': msg,
        'sig': signed_msg.signature.hex(),
        'name': contract_name,
        'inputs': c_inputs,
        'sources': sources,
        'sourceFile': f'ev-cli/{contract_file_name}'
    }
    # click.echo(deploy_json)
    # --ETHVIGIL API CALL---
    r = requests.post(ctx_obj['settings']['INTERNAL_API_ENDPOINT'] + '/deploy', json=deploy_json)
    if verbose:
        click.echo('EthVigil deploy response: ')
        click.echo(r.text)
    if r.status_code == requests.codes.ok:
        click.echo(f'Contract {contract_name} deployed successfully')
        r = r.json()
        click.echo(f'Contract Address: {r["data"]["contract"]}')
        click.echo(f'Deploying tx: {r["data"]["hash"]}')
    else:
        click.echo('Contract deployment failed')


@cli.command()
@click.argument('contract', required=True)
@click.argument('url', required=True)
@click.pass_obj
def registerhook(ctx_obj, contract, url):
    headers = {'accept': 'application/json', 'Content-Type': 'application/json',
               'X-API-KEY': ctx_obj['settings']['ETHVIGIL_API_KEY']}
    msg = 'dummystring'
    message_hash = encode_defunct(text=msg)
    sig_msg = Account.sign_message(message_hash, ctx_obj['settings']['PRIVATEKEY'])
    method_args = {
        "msg": msg,
        "sig": sig_msg.signature.hex(),
        "key": ctx_obj['settings']['ETHVIGIL_API_KEY'],
        "type": "web",
        "contract": contract,
        "web": url
    }
    r = requests.post(url=f'{ctx_obj["settings"]["INTERNAL_API_ENDPOINT"]}/hooks/add', json=method_args, headers=headers)
    click.echo(r.text)
    if r.status_code == requests.codes.ok:
        r = r.json()
        if not r['success']:
            click.echo('Failed to register webhook with Ethvigil API...')
        else:
            hook_id = r["data"]["id"]
            click.echo('Succeeded in registering webhook with Ethvigil API...')
            click.echo(f'EthVigil Hook ID: {hook_id}')
    else:
        click.echo('Failed to register webhook with Ethvigil API...')


@cli.command()
@click.argument('contractaddress', required=True)
@click.argument('hookid', required=True)
@click.argument('events', required=False)
@click.pass_obj
def addhooktoevent(ctx_obj, contractaddress, hookid, events):
    msg = 'dummystring'
    message_hash = encode_defunct(text=msg)
    sig_msg = Account.sign_message(message_hash, ctx_obj['settings']['PRIVATEKEY'])
    events_to_be_registered_on = list()
    if not events:
        events_to_be_registered_on.append('*')
    else:
        for each in events.split(','):
            events_to_be_registered_on.append(each)
    method_args = {
        "msg": msg,
        "sig": sig_msg.signature.hex(),
        "key": ctx_obj['settings']['ETHVIGIL_API_KEY'],
        "type": "web",
        "contract": contractaddress,
        "id": hookid,
        "events": events_to_be_registered_on
    }
    headers = {'accept': 'application/json', 'Content-Type': 'application/json',
               'X-API-KEY': ctx_obj['settings']['ETHVIGIL_API_KEY']}
    click.echo(f'Registering | hook ID: {hookid} | events: {events_to_be_registered_on} | contract: {contractaddress}')
    r = requests.post(url=f'{ctx_obj["settings"]["INTERNAL_API_ENDPOINT"]}/hooks/updateEvents', json=method_args,
                      headers=headers)
    click.echo(r.text)
    if r.status_code == requests.codes.ok:
        r = r.json()
        if r['success']:
            click.echo('Succeeded in adding hook')
        else:
            click.echo('Failed to add hook')
            return
    else:
        click.echo('Failed to add hook')
        return


@cli.command()
@click.argument('contractaddress', required=True)
@click.argument('hookid', required=True)
@click.pass_obj
def enabletxmonitor(ctx_obj, contractaddress, hookid):
    # enable tx monitoring on contract
    msg = 'dummystring'
    message_hash = encode_defunct(text=msg)
    sig_msg = Account.sign_message(message_hash, ctx_obj['settings']['PRIVATEKEY'])
    method_args = {
        "msg": msg,
        "sig": sig_msg.signature.hex(),
        "key": ctx_obj['settings']['ETHVIGIL_API_KEY'],
        "type": "web",
        "contract": contractaddress,
        "id": hookid,
        "action": "set"
    }
    headers = {'accept': 'application/json', 'Content-Type': 'application/json',
               'X-API-KEY': ctx_obj["settings"]["ETHVIGIL_API_KEY"]}
    r = requests.post(url=f'{ctx_obj["settings"]["INTERNAL_API_ENDPOINT"]}/hooks/transactions', json=method_args,
                      headers=headers)
    click.echo(r.text)
    if r.status_code == requests.codes.ok:
        r = r.json()
        if r['success']:
            click.echo('Succeded in adding hook to monitor all contract txs')
        else:
            click.echo('Failed to add hook to monitor on all contract txs...')
    else:
        click.echo('Failed to add hook to monitor on all contract txs...')


@cli.command()
@click.argument('contractaddress', required=True)
@click.option('--verbose', 'verbose', type=bool, default=False)
@click.pass_obj
def getoas(ctx_obj, contractaddress, verbose):
    a_data = ev_login(ctx_obj['settings']['INTERNAL_API_ENDPOINT'], ctx_obj['settings']['PRIVATEKEY'], verbose=False)
    registered_contracts = list(filter(lambda x: x['address'] == to_normalized_address(contractaddress), a_data['contracts']))
    if verbose:
        click.echo(registered_contracts)
    if registered_contracts:
        click.echo(f'{ctx_obj["settings"]["INTERNAL_API_ENDPOINT"]}/swagger/{to_normalized_address(contractaddress)}/?key={ctx_obj["settings"]["ETHVIGIL_API_KEY"]}')
    else:
        click.echo(f'Contract {contractaddress} not registered on EthVigil')


if __name__ == '__main__':
    cli()
