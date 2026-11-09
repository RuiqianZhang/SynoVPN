#!/usr/bin/env python3
"""Build native Go binaries + a complete DSM SPK. Never emits an SPK without charon."""
import argparse, hashlib, io, json, os, pathlib, shutil, struct, subprocess, sys, tarfile, zlib

ROOT = pathlib.Path(__file__).resolve().parents[1]
ARCHES = {"amd64": ("linux/amd64", "x86_64", 62), "arm64": ("linux/arm64", "rtd1296 rtd1619b", 183)}
TARGETS = {"sa6400": {"arch":"amd64", "package_arch":"epyc7002", "os_min_ver":"7.4.1-90080", "reported_dsm":"7.4.1-90080 Update 1"}}

def resolve_target(arch, target):
    if target:
        selected=TARGETS[target]
        if arch and arch!=selected['arch']:
            raise SystemExit(f'{target} requires {selected["arch"]}; refusing the incompatible architecture {arch}')
        arch=selected['arch']
        return arch,selected['package_arch'],selected['os_min_ver']
    if not arch:raise SystemExit('Specify --target sa6400 or --arch amd64/arm64')
    return arch,ARCHES[arch][1],'7.2-64570'

def run(args, **kwargs):
    subprocess.run(args, cwd=ROOT, check=True, **kwargs)

def licenses(go, env):
    template='{{with .Module}}{{.Path}}|{{.Dir}}{{end}}'
    output=subprocess.check_output([go,'list','-deps','-f',template,'./cmd/synovpn'],cwd=ROOT,env=env,text=True)
    entries={}
    for line in output.splitlines():
        if '|' not in line: continue
        name,directory=line.split('|',1)
        if name=='synovpn': continue
        directory=pathlib.Path(directory) if directory else ROOT/'vendor'/name
        if not directory.is_dir(): continue
        entries[name]=directory
    result={}
    for name,directory in sorted(entries.items()):
        for path in directory.iterdir():
            if path.is_file() and path.name.upper().startswith(('LICENSE','COPYING','NOTICE','AUTHORS')):
                result[name+'/'+path.name]=path.read_bytes()
    return result

def elf(path, machine):
    raw = path.read_bytes()
    if raw[:4] != b'\x7fELF' or raw[4] != 2 or struct.unpack_from('<H', raw, 18)[0] != machine:
        raise SystemExit(f'Wrong or missing ELF architecture: {path}')
    # A bundled static runtime avoids a DSM glibc or dynamic-loader dependency.
    phoff = struct.unpack_from('<Q', raw, 32)[0]
    entsize, count = struct.unpack_from('<HH', raw, 54)
    for i in range(count):
        if struct.unpack_from('<I', raw, phoff + i * entsize)[0] == 3:
            raise SystemExit(f'Dynamic ELF interpreter is not permitted: {path}')

def png(size):
    # Checked-in, antialiased artwork; regenerate with python3 tools/icon.py.
    return (ROOT/'packaging/ui/images'/f'icon_{size}.png').read_bytes()


def add(tar, name, data=None, executable=False, link=None, hardlink=None):
    item=tarfile.TarInfo(name);item.uid=item.gid=0;item.uname=item.gname='root';item.mtime=1793577600
    item.mode=0o755 if executable else 0o644
    if link is not None: item.type=tarfile.SYMTYPE;item.linkname=link;tar.addfile(item);return
    if hardlink is not None: item.type=tarfile.LNKTYPE;item.linkname=hardlink;tar.addfile(item);return
    item.size=len(data);tar.addfile(item,io.BytesIO(data))

def main():
    p=argparse.ArgumentParser();p.add_argument('--arch',choices=ARCHES);p.add_argument('--target',choices=TARGETS);p.add_argument('--go',default='go');p.add_argument('--runtime',type=pathlib.Path);p.add_argument('--build-runtime',action='store_true');p.add_argument('--smoke',action='store_true');p.add_argument('--smoke-local',action='store_true',help='run engine verification inside the isolated NAS build container');p.add_argument('--binaries-only',action='store_true');p.add_argument('--reuse-verified-runtime',action='store_true',help='repack the exact NAS-verified amd64 charon; does not claim DSM deployment validation');args=p.parse_args()
    args.arch,metadata,min_dsm=resolve_target(args.arch,args.target)
    platform,_,machine=ARCHES[args.arch]
    if not args.binaries_only:
        if args.smoke and args.smoke_local:raise SystemExit('Choose --smoke or --smoke-local, not both')
        if args.target and not (args.smoke or args.smoke_local or args.reuse_verified_runtime):raise SystemExit('Model-specific SPKs require engine verification; no unverified target package was produced.')
        if args.smoke_local:
            if sys.platform!='linux' or not pathlib.Path('/.dockerenv').exists():raise SystemExit('--smoke-local must run inside the isolated Linux build container')
            status=pathlib.Path('/proc/self/status').read_text()
            caps=next(line.split()[1] for line in status.splitlines() if line.startswith('CapEff:'))
            if not int(caps,16)&(1<<12):raise SystemExit('Build-container verification requires NET_ADMIN in its private network namespace')
        if (args.build_runtime or args.smoke) and shutil.which('docker') is None:raise SystemExit('Docker is unavailable. Run this build on the NAS Docker host or another Linux/Docker host. No SPK was produced.')
    build=ROOT/'build';build.mkdir(exist_ok=True)
    env=dict(os.environ,GOOS='linux',GOARCH=args.arch,CGO_ENABLED='0',GOAMD64='v1')
    for command,name in [('synovpn','synovpn'),('vici-probe','vici-probe')]:
        run([args.go,'build','-trimpath','-ldflags=-s -w','-o',str(build/f'{name}-linux-{args.arch}'),f'./cmd/{command}'],env=env)
    if args.binaries_only:return
    runtime=(args.runtime or ROOT/'runtime'/args.arch).resolve()
    if args.build_runtime:
        run(['docker','build','--platform',platform,'-f','tools/runtime.Dockerfile','--target','runtime','--output',f'type=local,dest={runtime}','.'])
    if not (runtime/'charon').is_file():
        raise SystemExit('No static strongSwan runtime. Re-run with --build-runtime on a Docker host. No incomplete SPK was produced.')
    elf(runtime/'charon',machine);elf(build/f'synovpn-linux-{args.arch}',machine)
    if args.reuse_verified_runtime:
        verified='4c275a7ef2826eed2465e0cbd256489d394582ea3c2f88b7a1db0e28fa1cf4c4'
        if args.arch!='amd64' or hashlib.sha256((runtime/'charon').read_bytes()).hexdigest()!=verified:
            raise SystemExit('Runtime differs from the exact NAS-verified static engine; a fresh engine smoke is required.')
    if args.smoke:
        image=f'synovpn-vici-smoke:{args.arch}'
        run(['docker','build','--platform',platform,'-f','tools/runtime.Dockerfile','--target','smoke','--build-arg',f'PROBE=build/vici-probe-linux-{args.arch}','-t',image,'.'])
        run(['docker','run','--rm','--platform',platform,'--cap-add=NET_ADMIN','--cap-add=NET_RAW',image])
    if args.smoke_local:
        smoke_env=dict(os.environ,SYNOVPN_SMOKE_CHARON=str(runtime/'charon'),SYNOVPN_SMOKE_PROBE=str(build/f'vici-probe-linux-{args.arch}'))
        run(['/bin/sh','tools/runtime-smoke.sh'],env=smoke_env)
    notices=licenses(args.go,env)
    data=io.BytesIO()
    with tarfile.open(fileobj=data,mode='w:gz',format=tarfile.USTAR_FORMAT) as tar:
        add(tar,'bin/synovpn',(build/f'synovpn-linux-{args.arch}').read_bytes(),True)
        add(tar,'ui/app.cgi',hardlink='bin/synovpn',executable=True)
        add(tar,'ui/config',(ROOT/'packaging/ui/config').read_bytes())
        for size in (16,24,32,48,64,72,128,256):add(tar,f'ui/images/icon_v8_{size}.png',png(size))
        for f in sorted(runtime.rglob('*')):
            if f.is_file():add(tar,'runtime/'+f.relative_to(runtime).as_posix(),f.read_bytes(),f.name=='charon')
        for f in sorted((ROOT/'packaging/engine').iterdir()):
            if f.is_file():add(tar,'engine/'+f.name,f.read_bytes().replace(b'\r\n',b'\n'))
        add(tar,'engine/synovpn',hardlink='bin/synovpn',executable=True)
        add(tar,'engine/charon',hardlink='runtime/charon',executable=True)
        for name in ('README.md','SECURITY.md','LICENSE','THIRD_PARTY.md'):
            add(tar,name,(ROOT/name).read_bytes())
        for f in sorted((ROOT/'licenses/runtime').glob('*')):
            if f.is_file():add(tar,'licenses/runtime/'+f.name,f.read_bytes())
        add(tar,'runtime/source/build-runtime.sh',(ROOT/'tools/compile-runtime.sh').read_bytes(),True)
        if args.target:add(tar,'build-target.json',json.dumps({'model':args.target.upper(),**TARGETS[args.target],'dsm_validation':'not-yet-tested-on-device','runtime_verification':'reused-exact-NAS-verified-sha256' if args.reuse_verified_runtime else 'VICI-smoke-this-build','runtime_sha256':hashlib.sha256((runtime/'charon').read_bytes()).hexdigest(),'container_runtime':'ContainerManager>=1432'},indent=2).encode())
        for name,content in notices.items():add(tar,'licenses/go/'+name,content)
    info=f'''package="SynoVPN"
displayname="SynoVPN"
version="0.5.0-9"
description="DSM session authenticated per-user certificate IKEv2 device portal. Preview release: NAS validation required."
arch="{metadata}"
os_min_ver="{min_dsm}"
maintainer="SynoVPN Local Development"
thirdparty="yes"
beta="yes"
dsmuidir="ui"
dsmappname="local.synovpn.portal"
startable="yes"
install_dep_packages="ContainerManager>=20.10.23-1432"
silent_install="no"
silent_upgrade="yes"
silent_uninstall="no"
'''
    tag=f'{args.target}-{metadata}' if args.target else args.arch
    dist=ROOT/'dist';dist.mkdir(exist_ok=True);spk=dist/f'SynoVPN-0.5.0-9-{tag}.spk'
    with tarfile.open(spk,'w',format=tarfile.USTAR_FORMAT) as tar:
        add(tar,'INFO',info.encode());add(tar,'package.tgz',data.getvalue())
        add(tar,'PACKAGE_ICON.PNG',png(64));add(tar,'PACKAGE_ICON_256.PNG',png(256))
        for f in sorted((ROOT/'packaging').rglob('*')):
            if f.is_file() and f.relative_to(ROOT/'packaging').parts[0] not in ('ui','engine'):
                add(tar,f.relative_to(ROOT/'packaging').as_posix(),f.read_bytes().replace(b'\r\n',b'\n'),f.parent.name=='scripts')
    digest=hashlib.sha256(spk.read_bytes()).hexdigest();spk.with_suffix('.spk.sha256').write_text(f'{digest}  {spk.name}\n')
    print(spk)

if __name__=='__main__':main()
