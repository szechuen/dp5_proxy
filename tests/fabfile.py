from fabric.api import run, task, cd, env, shell_env, settings

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

