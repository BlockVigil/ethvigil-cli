import click
import requests
from eth_account.messages import defunct_hash_message
from eth_account.account import Account
import json
import os
import pwd
from eth_utils import to_normalized_address

CONTEXT_SETTINGS = dict(
    help_option_names=['-h', '--help']
)

CLEAN_SLATE_SETTINGS = {
  "PRIVATEKEY": None,
  "INTERNAL_API_ENDPOINT": "https://beta.ethvigil.com/api",
  "REST_API_ENDPOINT": None,
  "ETHVIGIL_USER_ADDRESS": "",
  "ETHVIGIL_API_KEY": ""

}


@click.group(context_settings=CONTEXT_SETTINGS)
@click.pass_context
def cli(ctx):
    try:
        with open(pwd.getpwuid(os.getuid()).pw_dir+'/.ethvigil/settings.json', 'r') as f:
            s = json.load(f)
    except:
        # settings file does not exist, copy over settings.null.json
        try:
            os.stat(pwd.getpwuid(os.getuid()).pw_dir+'/.ethvigil')
        except:
            os.mkdir(pwd.getpwuid(os.getuid()).pw_dir+'/.ethvigil')
        # create settings file from empty JSON file
        with open(pwd.getpwuid(os.getuid()).pw_dir+'/.ethvigil/settings.json', 'w') as f2:
            json.dump(obj=CLEAN_SLATE_SETTINGS, fp=f2)
        s = CLEAN_SLATE_SETTINGS
    finally:
        ctx.obj = {'settings': s}


def ev_login(internal_api_endpoint, private_key, verbose=False):
    msg = "Trying to login"
    message_hash = defunct_hash_message(text=msg)
    signed_msg = Account.signHash(message_hash, private_key)
    # --THUNDERVIGIL API CALL---
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


def ev_signup(internal_api_endpoint, invite_code, private_key):
    msg = "Trying to signup"
    message_hash = defunct_hash_message(text=msg)
    signed_msg = Account.signHash(message_hash, private_key)
    # --ETHVIGIL API CALL to /signup---
    try:
        r = requests.post(internal_api_endpoint + '/signup', json={
            'msg': msg, 'sig': signed_msg.signature.hex(), 'code': invite_code
        })
    except:
        return False
    else:
        print(r.url)
        print(r.text)
        if r.status_code == requests.codes.ok:
            return r.json()
        else:
            return False


def fill_rest_api_endpoint(new_endpoint):
    with open(pwd.getpwuid(os.getuid()).pw_dir+'/.ethvigil/settings.json', 'w') as f:
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
        # click.echo('Choosing EthVigil Alpha instance https://alpha.ethvigil.com/api ...')
        invite_code = click.prompt('Enter your invite code')
        new_account = Account.create('RANDOM ENTROPY WILL SUCK YOUR SOUL')
        signup_status = ev_signup(ctx_obj['settings']['INTERNAL_API_ENDPOINT'], invite_code, new_account.key.hex())
        if not signup_status:
            click.echo('Signup failed')
            return
        else:
            ctx_obj['settings']['PRIVATEKEY'] = new_account.key.hex()
            ctx_obj['settings']['ETHVIGIL_USER_ADDRESS'] = new_account.address
            with open(pwd.getpwuid(os.getuid()).pw_dir+'/.ethvigil/settings.json', 'w') as f:
                json.dump(ctx_obj['settings'], f)
            click.echo('Sign up succeeded...')
            click.echo('Logging in with your credentials...')
            login_data = ev_login(ctx_obj['settings']['INTERNAL_API_ENDPOINT'], new_account.key.hex(), verbose)
            if login_data:
                ctx_obj['settings']['ETHVIGIL_API_KEY'] = login_data['key']
                ctx_obj['settings']['REST_API_ENDPOINT'] = login_data['api_prefix']
                with open(pwd.getpwuid(os.getuid()).pw_dir+'/.ethvigil/settings.json', 'w') as f:
                    json.dump(ctx_obj['settings'], f)
                click.echo('You have signed up and logged in successfully to EthVigil Alpha')
                click.echo('---YOU MIGHT WANT TO COPY THESE DETAILS TO A SEPARATE FILE---')
                click.echo('===Private key (that signs messages to interact with EthVigil APIs===')
                click.echo(ctx_obj['settings']['PRIVATEKEY'])
                click.echo('===ETHEREUM hexadecimal address corresponding to above private key===')
                click.echo(ctx_obj['settings']['ETHVIGIL_USER_ADDRESS'])
            else:
                click.echo('Login failed with credentials. Run `ev-cli reset`.')
    else:
        click.echo("A registered private key exists for this ev-cli installation. Run ev-cli reset if you wish"
                   " to do a fresh install")


@cli.command()
@click.pass_obj
def reset(ctx_obj):
    if click.confirm('Do you want to reset the current EthVigil CLI configuration and state?'):
        try:
            with open(pwd.getpwuid(os.getuid()).pw_dir+'/.ethvigil/settings.json', 'w') as f2:
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
    account_data = ev_login(internal_api_endpoint=ctx_obj['settings']['INTERNAL_API_ENDPOINT'],
                            private_key=ctx_obj['settings']['PRIVATEKEY'],
                            verbose=verbose_flag)
    fill_rest_api_endpoint(ctx_obj, account_data['api_prefix'])


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
              help='constructor input values as a JSON list. '
                   'Eg: \'["abced", "0x008604d4997a15a77f00CA37aA9f6A376E129DC5"]\' '
                   'for constructor inputs of type (string, address). '
                   'Can be left empty if there are no inputs accepted by the constructor')
@click.option('--verbose', 'verbose', type=bool, default=False)
@click.argument('contract', type=click.File('r'))
@click.pass_obj
def deploy(ctx_obj, contract_name, inputs, verbose, contract):
    """
    Deploys a smart contract from the solidity source code specified

    CONTRACT: path to the solidity file

    Usage example: ev-cli deploy ../token.sol --contractName=FixedSupplyToken --constructorInputs='JSON representation of the constructor arguments'
    """
    contract_src = ""
    if verbose:
        click.echo('Got constructor inputs: ')
        click.echo(inputs)
    if inputs:
        c_inputs = json.loads(inputs)
    else:
        c_inputs = list()  # an empty list
    while True:
        chunk = contract.read(1024)
        if not chunk:
            break
        contract_src += chunk

    msg = "Trying to deploy"
    message_hash = defunct_hash_message(text=msg)
    # deploy from alpha account
    signed_msg = Account.signHash(message_hash, ctx_obj['settings']['PRIVATEKEY'])
    deploy_json = {
        'msg': msg,
        'sig': signed_msg.signature.hex(),
        'name': contract_name,
        'inputs': c_inputs,
        'code': contract_src
    }
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
    message_hash = defunct_hash_message(text=msg)
    sig_msg = Account.signHash(message_hash, ctx_obj['settings']['PRIVATEKEY'])
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
    message_hash = defunct_hash_message(text=msg)
    sig_msg = Account.signHash(message_hash, ctx_obj['settings']['PRIVATEKEY'])
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
    message_hash = defunct_hash_message(text=msg)
    sig_msg = Account.signHash(message_hash, ctx_obj['settings']['PRIVATEKEY'])
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
