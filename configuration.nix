{ config, lib, pkgs, ... }:

{
  imports = [
    <nixpkgs/nixos/modules/installer/cd-dvd/installation-cd-graphical-calamares-plasma6.nix>

  ];

  boot.kernelModules = [ "ehci_pci" "uhci_hcd" "ohci_hcd" ];

  # Load hardened kernel
  boot.kernelPackages = lib.mkDefault pkgs.linuxPackages_hardened;

  # Disable ptrace
  boot.kernel.sysctl."kernel.yama.ptrace_scope" = lib.mkForce 2;

  #
  boot.kernel.sysctl."kernel.kptr_restrict" = lib.mkForce 2;

  # Disable BPF just in time compiler
  boot.kernel.sysctl."net.core.bpf_jit_enable" = lib.mkDefault false;
  boot.kernel.sysctl."kernel.unprivileged_bpf_disabled" = lib.mkOverride 500 1;
  boot.kernel.sysctl."net.core.bpf_jit_harden" = lib.mkForce 2;

  # Disable ftrace
  boot.kernel.sysctl."kernel.ftrace_enabled" = lib.mkDefault false;

  #
  boot.kernel.sysctl."kernel.randomize_va_space" = lib.mkForce 2;

  # Prevent kernel dumping exploit
  boot.kernel.sysctl."fs.suid_dumpable" = lib.mkOverride 500 0;

  # Restrict kernel log access
  boot.kernel.sysctl."kernel.dmesg_restrict" = lib.mkForce 1;
  boot.consoleLogLevel = lib.mkOverride 500 3;

  #
  boot.kernel.sysctl."vm.unprivileged_userfaultfd" = lib.mkForce 0;

  #
  boot.kernel.sysctl."kernel.kexec_load_disabled" = lib.mkForce 1;

  # Disable sysreq
  boot.kernel.sysctl."kernel.sysrq" = lib.mkForce 0;

  # Disable user space cloning
  boot.kernel.sysctl."kernel.unprivileged_userns_clone" = lib.mkForce 0;

  # Disable dynamic kernel module loading
  boot.kernel.sysctl."kernel.modules_disabled" = lib.mkForce 1;

  # Disable default kernel modules
  boot.initrd.includeDefaultModules = false;
  boot.initrd.kernelModules = [];

  # Disable specific  USB funtionalities
  #boot.kernelPatches = [
  #  {
  #    name = "disable-usb-networking-and-storage";
  #    patch = null;
  #    extraConfig = ''
  #      USB_NET_DRIVERS n
  #      USB_STORAGE n
  #    '';
  #  }
  #];

  # Set kernel params
  boot.kernelParams = [

    # Enable memory allocation debugger
    "slub_debug=FZPU"

    # Scrub memory before reuse
    "init_on_alloc=1"
    "init_on_free=1"

    # Randomise page allocation
    "page_alloc.shuffle=1"

    # Panic on uncorrectable memory access (mostly useful for systems with ECC memory)
    "mce=0"

    # Randomise kernel stack offset
    "randomize_kstack_offset=on"
  ];

  # Blacklist insecure kernel modules
  boot.blacklistedKernelModules = [

    # Obscure network protocols
    "ax25"
    "netrom"
    "rose"

    # Old or rare or insufficiently audited filesystems
    "adfs"
    "affs"
    "bfs"
    "befs"
    "cramfs"
    "efs"
    "erofs"
    "exofs"
    "freevxfs"
    "f2fs"
    "hfs"
    "hpfs"
    "jfs"
    "minix"
    "nilfs2"
    "ntfs"
    "omfs"
    "qnx4"
    "qnx6"
    "sysv"
    "ufs"

    # Misc
    "cups"
    "bluetooth"
    "xhci_pci"
  ];

  # Disable IPV6
  boot.kernel.sysctl."net.ipv6.conf.all.disable_ipv6" = lib.mkForce 1;
  boot.kernel.sysctl."net.ipv6.conf.default.disable_ipv6" = lib.mkForce 1;
  boot.kernel.sysctl."net.ipv6.conf.lo.disable_ipv6" = lib.mkForce 1;

  # Prevent SYN exploit
  boot.kernel.sysctl."net.ipv4.tcp_syncookies" = lib.mkForce 1;
  boot.kernel.sysctl."net.ipv4.tcp_syn_retries" = lib.mkForce 2;
  boot.kernel.sysctl."net.ipv4.tcp_synack_retries" = lib.mkForce 2;
  boot.kernel.sysctl."net.ipv4.tcp_max_syn_backlog" = lib.mkForce 4096;

  #
  boot.kernel.sysctl."net.ipv4.tcp_rfc1337" = lib.mkForce 1;

  #
  boot.kernel.sysctl."net.ipv4.conf.all.rp_filter" = lib.mkForce 1;
  boot.kernel.sysctl."net.ipv4.conf.default.rp_filter" = lib.mkForce 1;

  # Disable redirects
  boot.kernel.sysctl."net.ipv4.conf.all.accept_redirects" = lib.mkForce 0;
  boot.kernel.sysctl."net.ipv4.conf.default.accept_redirects" = lib.mkForce 0;
  boot.kernel.sysctl."net.ipv4.conf.all.secure_redirects" = lib.mkForce 0;
  boot.kernel.sysctl."net.ipv4.conf.default.secure_redirects" = lib.mkForce 0;
  boot.kernel.sysctl."net.ipv4.conf.all.send_redirects" = lib.mkForce 0;
  boot.kernel.sysctl."net.ipv4.conf.default.send_redirects" = lib.mkForce 0;

  #
  boot.kernel.sysctl."net.ipv4.conf.all.accept_source_route" = lib.mkForce 0;
  boot.kernel.sysctl."net.ipv4.conf.default.accept_source_route" = lib.mkForce 0;
  boot.kernel.sysctl."net.ipv4.conf.icmp_echo_ignore_all" = lib.mkForce 1;

  # Log martian packets
  boot.kernel.sysctl."net.ipv4.conf.all.log_martian" = lib.mkDefault true;
  boot.kernel.sysctl."net.ipv4.conf.default.log_martian" = lib.mkDefault true;

  # Ignore fake icmp error responses
  boot.kernel.sysctl."net.ipv4.icmp_ignore_bogus_error_responses" = lib.mkForce 1;

  # Prevent kernel image modification
  security.protectKernelImage = lib.mkDefault true;

  # Prevent user space cloning
  security.unprivilegedUsernsClone = lib.mkDefault false;

  # Prevent dynamic kernel module loading
  security.lockKernelModules = lib.mkDefault true;

  # Use scudo memory allocator
  environment.memoryAllocator.provider = lib.mkDefault "scudo";
  environment.variables.SCUDO_OPTIONS = lib.mkDefault "ZeroContents=1";

  # Disable multithreading
  security.allowSimultaneousMultithreading = lib.mkDefault false;

  # Force page table isolation
  security.forcePageTableIsolation = lib.mkDefault true;

  # Flush L1 data cache before entering guest VM
  security.virtualisation.flushL1DataCache = lib.mkDefault "always";

  # Enable nftables firewall
  networking.nftables.enable = true;
  networking.firewall = {
    enable = true;
    allowedTCPPorts = [ 80 43 ];
  };

  # Enable AppArmor
  security.apparmor.enable = true;
  # security.apparmor.policies."application".profile = ''

  # Enable ClamAV virus protection
  services.clamav.daemon.enable = true;
  services.clamav.updater.enable = true;

  services.sshd.enable = false;

  services.fail2ban.enable = true;

  # services.xserver = {
   # enable = true;
   # layout = "uk"; # Adjust to your keyboard layout
   # displayManager.sddm.enable = true;
   # desktopManager.plasma6 = {
   #   enable = true;
   #   wayland = true;
   # };
  #};

  # Configure systemd service exposure
  
  environment.systemPackages = with pkgs; [
    wget
    linuxKernel.packages.linux_hardened.chipsec
    uefitool
    uefisettings
    uefi-firmware-parser
    ed2k-uefi-shell
    sbsigntool
    fiano
    efitools
    ifrextractor-rs
    yara-x
    quark-engine
    yara
    snort
    firehol
    opensnitch
    opensnitch-ui
    vscodium-fhs
    firmware-manager
    ipxe
    linuxKernel.packages.linux_6_9_hardened.r8168
  ];
}
