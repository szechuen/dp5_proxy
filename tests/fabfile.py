from fabric.api import run, task, cd, env, shell_env, settings, put, roles, execute, prefix, get

env.use_ssh_config = True

def pythonpath(path):
    home=run('echo $HOME')
    return shell_env(PYTHONPATH="{}/{}/build:".format(home,path))

@task
def clone(path='dp5'):
    if run("test -d {}/code".format(path), warn_only=True).succeeded:
       print "Already exists"
       return
    run("mkdir -p {}".format(path))
    with cd(path):
        run("git clone git@git-crysp.uwaterloo.ca:dp5/code")
        with cd("code"):
            run("git submodule init")
            run("git submodule update")


@task
def pull(path='dp5'):
    with cd(path+"/code"):
        run("git pull")

@task
def build(path='dp5', rebuild='no'):
    builddir = "{}/build".format(path)
    if rebuild=='yes':
        run("rm -rf " + builddir, warn_only=True)
    run("mkdir -p " + builddir)
    with cd(builddir):
        run("cmake ../code")
        run("make")
        run("mkdir -p ../test")
        run("ln -sfv libdp5clib.so ../test")

@task
def test(path='dp5'):
    with settings(warn_only=True):
        # run all tests 
        with cd(path + "/build"):
            run("make test")
            with shell_env(PYTHONPATH=".:"):
                run("python ../code/dp5test.py")
            run("mkdir -p logs")
            run("python ../code/dp5cffi_test.py")

@roles("regserver")
@task
def setup_rs(path='dp5'):
    put("regserver.cfg", path+"/test/regserver.cfg")

@roles("regserverCB")
@task
def setup_rscb(path='dp5'):
    put("regserverCB.cfg", path+"/test/regserverCB.cfg")
       
@task
def setup_onels(path, config_file, combined):
    put(config_file, path+"/test/"+config_file)

def run_lstask(lstask, *args, **kwargs):
    if kwargs.get("combined", False):
        lss = env["roledefs"]["lookupserversCB"]
    else:
        lss = env["roledefs"]["lookupservers"]

    for i in range(len(lss)):
        config_file = "lookupserver{}{}.cfg".format(kwargs.get("combined", False) and "CB" or "", i)
        execute(lstask, *args, config_file=config_file, host=lss[i], **kwargs)

@task
def setup_ls(path='dp5'):
    run_lstask(setup_onels, path, combined=True)
    run_lstask(setup_onels, path, combined=False)

@roles('servers')
@task
def clean(path='dp5'):
    run("killall python && killall -9 python", warn_only=True)
    run("mkdir -p {0}/test/testcerts {0}/test/logs".format(path))
    put("../testcerts/*", "{}/test/testcerts/".format(path))

    with cd(path+"/test"):
        run("rm -rf {}/test/store-*".format(path))
        run("ln -sfv ../build/libdp5clib.so .")


@task
def setup(path='dp5'):
    execute("clean", path)
    execute("setup_rs", path)
    execute("setup_rscb", path)
    execute("setup_ls", path)


@task
def virtualenv(path="dp5"):    
    # clean up existing venv
    run("rm -rf {}/venv".format(path))

    home = run("echo $HOME")

    # install virtualenv
    # FIXME: this assumes that we are running python2.7. Also, we can skip this
    # in places where virtualenv is already installed
    run("mkdir -p {0}/.python/lib {0}/.python/bin".format(path))
    with shell_env(PYTHONPATH="{}/{}/.python/lib:".format(home, path)):
        run("easy_install -d ~/{0}/.python/lib -s ~/{0}/.python/bin virtualenv".format(path))
        run("{0}/.python/bin/virtualenv {0}/venv".format(path))
       
    with prefix("source ~/{}/venv/bin/activate".format(path)):
        run("pip install requests twisted pyopenssl cherrypy")

@roles('client')
@task
def setup_client(path='dp5'):
    run("killall python && killall -9 python", warn_only=True)
    run("mkdir -p {0}/test/logs".format(path))
    with cd(path+"/test"):
        run("ln -sfv ../build/libdp5clib.so .")
    put("client.cfg", path+"/test/")

@roles('client')
@task
def make_users(num_users, path='dp5'):
    with cd(path+"/test"):
        run("python ../code/users.py {0} users.{0}".format(num_users))
    
@roles('client')
@task
def run_client(users, path='dp5'):
    with cd(path+"/test"), prefix("source ~/{}/venv/bin/activate".format(path)), \
        shell_env(PYTHONPATH="../build:"):
        run("python ../code/dp5twistedclient.py client.cfg " + users)


@task
def run_server(config_file, path='dp5'):
    with cd(path+"/test"), prefix("source ~/{}/venv/bin/activate".format(path)), \
        shell_env(PYTHONPATH="../build:"):
        run("python ../code/dp5twistedserver.py " + config_file)


    
@task
def fake_epoch(users, path='dp5'):
  execute(create_fake_epoch, users, path)
  execute(deploy_fake_epoch, path)

@roles('client')
@task
def create_fake_epoch(users, path='dp5'):
  with cd(path+"/test"):
    run("python ../code/fakeprevepoch.py client.cfg " + users)
    get("fake", "%(path)s")

@roles('regserver')
@task
def deploy_fake_epoch(path='dp5'):
  put("fake/*", path+"/test/store-reg/data/")
  

  

