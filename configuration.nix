{ config, lib, pkgs, ... }:

{
  imports = [
    <nixpkgs/nixos/modules/installer/cd-dvd/installation-cd-graphical-calamares-plasma6.nix>

  ];

  boot.kernelModules = [];

  # Load hardened kernel
  boot.kernelPackages = mkDefault pkgs.linuxPackages_hardened;

  # Disable ptrace
  boot.kernel.sysctl."kernel.yama.ptrace_scope" = mkForce 2;

  #
  boot.kernel.sysctl."kernel.kptr_restrict" = mkForce 2;

  # Disable BPF just in time compiler
  boot.kernel.sysctl."net.core.bpf_jit_enable" = mkDefault false;
  boot.kernel.sysctl."kernel.unpriviledged_bpf_disabled" = mkOverride 500 1;
  boot.kernel.sysctl."net.core.bpf_jit_harden" = mkForce 2;

  # Disable ftrace
  boot.kernel.sysctl."kernel.ftrace_enabled" = mkDefault false;

  #
  boot.kernel.sysctl."kernel.randomize_va_space" = mkForce 2;

  # Prevent kernel dumping exploit
  boot.kernel.sysctl."fs.suid_dumpable" = mkOverride 500 0;

  # Restrict kernel log access
  boot.kernel.sysctl."kernel.dmesg_restrict" = mkForce 1;
  boot.consoleLogLevel = mkOverride 500 3;

  #
  boot.kernel.sysctl."vm.unpriviledged_userfaultfd" = mkForce 0;

  #
  boot.kernel.sysctl."kernel.kexec_load_disabled" = mkForce 1;

  # Disable sysreq
  boot.kernel.sysctl."kernel.sysrq" = mkForce 0;

  # Disable user space cloning
  boot.kernel.sysctl."kernel.unpriviledged_userns_clone" = mkForce 0;

  # Disable dynamic kernel module loading
  boot.kernel.sysctl."kernel.modules_disabled" = mkForce 1;

  # Disable default kernel modules
  boot.initrd.includeDefaultModules = false;
  boot.initrd.kernelModules = [];

  # Disable specific  USB funtionalities
  boot.kernelPatches = [
    {
      name = "disable-usb-networking-and-storage";
      patch = null;
      extraConfig = ''
        USB_NET_DRIVERS n
        USB_STORAGE n
      '';
    }
  ];

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
  boot.kernel.sysctl."net.ipv6.conf.all.disable_ipv6" = mkForce 1;
  boot.kernel.sysctl."net.ipv6.conf.default.disable_ipv6" = mkForce 1;
  boot.kernel.sysctl."net.ipv6.conf.lo.disable_ipv6" = mkForce 1;

  # Prevent SYN exploit
  boot.kernel.sysctl."net.ipv4.tcp_syncookies" = mkForce 1;
  boot.kernel.sysctl."net.ipv4.tcp_syn_retries" = mkForce 2;
  boot.kernel.sysctl."net.ipv4.tcp_synack_retries" = mkForce 2;
  boot.kernel.sysctl."net.ipv4.tcp_max_syn_backlog" = mkForce 4096;

  #
  boot.kernel.sysctl."net.ipv4.tcp_rfc1337" = mkForce 1;

  #
  boot.kernel.sysctl."net.ipv4.conf.all.rp_filter" = mkForce 1;
  boot.kernel.sysctl."net.ipv4.conf.default.rp_filter" = mkForce 1;

  # Disable redirects
  boot.kernel.sysctl."net.ipv4.conf.all.accept_redirects" = mkForce 0;
  boot.kernel.sysctl."net.ipv4.conf.default.accept_redirects" = mkForce 0;
  boot.kernel.sysctl."net.ipv4.conf.all.secure_redirects" = mkForce 0;
  boot.kernel.sysctl."net.ipv4.conf.default.secure_redirects" = mkForce 0;
  boot.kernel.sysctl."net.ipv4.conf.all.send_redirects" = mkForce 0;
  boot.kernel.sysctl."net.ipv4.conf.default.send_redirects" = mkForce 0;

  #
  boot.kernel.sysctl."net.ipv4.conf.all.accept_source_route" = mkForce 0;
  boot.kernel.sysctl."net.ipv4.conf.default.accept_source_route" = mkForce 0;
  boot.kernel.sysctl."net.ipv4.conf.icmp_echo_ignore_all" = mkForce 1;

  # Log martian packets
  boot.kernel.sysctl."net.ipv4.conf.all.log_martian" = mkDefault true;
  boot.kernel.sysctl."net.ipv4.conf.default.log_martian" = mkDefault true;

  # Ignore fake icmp error responses
  boot.kernel.sysctl."net.ipv4.icmp_ignore_bogus_error_responses" = mkForce 1;

  # Prevent kernel image modification
  security.protectKernelImage = mkDefault true;

  # Prevent user space cloning
  security.unpriviledgedUsernsClone = mkDefault false;

  # Prevent dynamic kernel module loading
  security.lockKernelModules = mkDefault true;

  # Use scudo memory allocator
  environment.memoryAllocator.provider = mkDefault "scudo";
  environment.variables.SCUDO_OPTIONS = mkDefault "ZeroContents=1";

  # Disable multithreading
  security.allowSimultaneousMultithreading = mkDefault false;

  # Force page table isolation
  security.forcePageTableIsolation = mkDefault true;

  # Flush L1 data cache before entering guest VM
  security.virtualisation.flushL1DataCache = mkDefault "always";

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

  services.xserver = {
    enable = true;
    layout = "uk"; # Adjust to your keyboard layout
    displayManager.sddm.enable = true;
    desktopManager.plasma6 = {
      enable = true;
      wayland = true;
    };
  };

  # Configure systemd service exposure

}
