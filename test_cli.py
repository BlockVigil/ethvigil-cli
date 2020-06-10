from click.testing import CliRunner
from click_cli import cli
import os

def read_file(location):
    src = ''
    file_obj = open(location, 'r')
    while True:
        chunk = file_obj.read(1024)
        if not chunk:
            break
        src += chunk
    return src


def ev_init(runner_obj, verbose="false"):
    print('\nAttempting to initialize...')
    init_response = runner_obj.invoke(cli, args=["init", "--verbose", verbose], input=os.getenv('ETHVIGIL_SIGNUP_CODE'), color=True)
    return init_response

def ev_deploy(runner_obj, dir, main_contract_file, contract_name, constructor_inputs, verbose="false"):
    deploy_args = [
        "deploy",
        f"{dir}/{main_contract_file}",
        "--contractName", contract_name,
        "--constructorInputs", constructor_inputs,
        "--verbose",
        verbose,
    ]
    deploy_response = runner_obj.invoke(cli, args=deploy_args, mix_stderr=True, color=True)
    return deploy_response

def ev_reset(runner_obj):
    reset_response = runner_obj.invoke(cli, args=["reset"], input='y', color=True)
    return reset_response

# # # signup, login and deploy using EthVigil APIs

def test_init_deploy_microblog_without_imports():
    runner = CliRunner()
    contract_file_obj = open('contracts/Microblog.sol', 'r')
    main_contract_src = ''
    # keep the microblog contract code handy
    while True:
        chunk = contract_file_obj.read(1024)
        if not chunk:
            break
        main_contract_src += chunk
    with runner.isolated_filesystem() as test_dir:
        init_response = ev_init(runner)
        assert init_response.exception == None or init_response.exit_code == 1  # existing data dir returns 1 on init
        print(init_response.output)

        # copy over contract file(s)
        f2 = open(test_dir+'/Microblog.sol', 'w')
        # print(f2)
        f2.write(main_contract_src)
        f2.close()

        print('\nAttempting to deploy Microblog.sol...')
        constructor_inputs = '["NewBlogTitle", "NewBlogOwner"]'
        deploy_response = ev_deploy(
            runner_obj=runner,
            dir=test_dir,
            main_contract_file='Microblog.sol',
            contract_name='Microblog',
            constructor_inputs=constructor_inputs
        )
        assert deploy_response.exception == None
        print(deploy_response.output)
        ## reset temp data directory credentials
        print('\nAttempting to reset local credentials...')
        reset_response = ev_reset(runner)
        print(reset_response.output)
        assert reset_response.exception == None

def test_init_deploy_erc20_with_imports():
    runner = CliRunner()
    main_contract_src = read_file('contracts/ERC20Mintable.sol')
    safe_math_src = read_file('contracts/SafeMath.sol')
    with runner.isolated_filesystem() as test_dir:
        init_response = ev_init(runner)
        assert init_response.exception == None or init_response.exit_code == 1  # existing data dir returns 1 on init
        print(init_response.output)

        # copy over contract file(s)
        f = open(test_dir + '/ERC20Mintable.sol', 'w')
        f.write(main_contract_src)
        f.close()

        f2 = open(test_dir + '/SafeMath.sol', 'w')
        f2.write(safe_math_src)
        f2.close()

        print('\nAttempting to deploy ERC20Mintable.sol...')
        constructor_inputs = '["TestTokenName", "SYMB", 18]'
        deploy_response = ev_deploy(
            runner_obj=runner,
            dir=test_dir,
            main_contract_file='ERC20Mintable.sol',
            contract_name='ERC20Mintable',
            constructor_inputs=constructor_inputs
        )
        assert deploy_response.exception == None
        print(deploy_response.output)
        ## reset temp data directory credentials
        print('\nAttempting to reset local credentials...')
        reset_response = ev_reset(runner)
        print(reset_response.output)
        assert reset_response.exception == None