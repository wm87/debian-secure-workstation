#!/usr/bin/env bash
set -euo pipefail

#################################################
# Debian-Security ISO-Image
#
# Stand 06.02.26:
# AppArmor-Profile, USB-Guard, SSH-Hardening etc.
# Software via Snap: Intellij, Pycharm, VSCode
# weitere Software via apt
#################################################

# =========================
# Trap setzen, damit Terminal nicht hängen bleibt
# =========================
trap 'stty echo; echo; exit' INT TERM EXIT

############################
# CONFIG
############################
ISO_URL="https://cdimage.debian.org/debian-cd/current/amd64/iso-cd/debian-13.3.0-amd64-netinst.iso"
ISO_OUT="debian-13.3.0-desktop-secure.iso"
WORKDIR="$PWD/work"

HOSTNAME="debian-secure"
DOMAIN="local"
NETWORK_TYPE="dhcp"

# TPM/LUKS Konfiguration
export AUTO_CONFIRM=true
export LUKS_KEYSLOT_TPM=1
export LUKS_KEYSLOT_BACKUP=7
export CRYPTDEV_NAME="cryptroot"

export TPM_LUKS_PCRS="0,2,4,7"  # Standard + Secure Boot PCR
# 0: Core System Firmware
# 2: Extended or Plug-in Code
# 4: Boot Manager (Grub, etc.)
# 7: Secure Boot Status

# =========================
# Funktion: Passwort-Eingabe mit Sternchen
# =========================
read_password() {
    local prompt="$1"
    local password=""
    local char=""
    local charcount=0

    echo -n "$prompt" >&2
    stty -echo

    while IFS= read -r -n1 -s char; do
        [[ -z $char ]] && {
            echo >&2
            break
        }
        if [[ $char == $'\177' || $char == $'\b' ]]; then
            if [ $charcount -gt 0 ]; then
                charcount=$((charcount - 1))
                password="${password%?}"
                echo -n $'\b \b' >&2
            fi
        else
            charcount=$((charcount + 1))
            password+="$char"
            echo -n '*' >&2
        fi
    done

    stty echo
    echo "$password"
}

# =========================
# Passwort-Validierung
# =========================
validate_password() {
    local pw="$1"

    if [[ ${#pw} -lt 8 ]]; then
        echo "❌ Passwort muss mindestens 8 Zeichen lang sein."
        return 1
    fi
    if ! [[ "$pw" =~ [A-Z] ]]; then
        echo "❌ Passwort muss mindestens einen Großbuchstaben enthalten."
        return 1
    fi
    if ! [[ "$pw" =~ [a-z] ]]; then
        echo "❌ Passwort muss mindestens einen Kleinbuchstaben enthalten."
        return 1
    fi
    if ! [[ "$pw" =~ [0-9] ]]; then
        echo "❌ Passwort muss mindestens eine Zahl enthalten."
        return 1
    fi
    if ! [[ "$pw" =~ [^a-zA-Z0-9] ]]; then
        echo "❌ Passwort muss mindestens ein Sonderzeichen enthalten."
        return 1
    fi

    return 0
}

# =========================
# 1. Benutzername und Passwort abfragen
# =========================
echo "=== Debian Installationskonfiguration ==="

# Benutzername abfragen
read -p "Benutzername eingeben [default: user]: " input_username
USERNAME="${input_username:-user}"

# Hauptpasswort abfragen
while true; do
    MAIN_PASSWORD=$(read_password "Haupt-Passwort eingeben (für Login & LUKS): ")
    MAIN_CONFIRM=$(read_password "Haupt-Passwort bestätigen: ")
    echo ""

    if [ "$MAIN_PASSWORD" != "$MAIN_CONFIRM" ]; then
        echo "❌ Passwörter stimmen nicht überein."
        continue
    fi

    if validate_password "$MAIN_PASSWORD"; then
        echo "✅ Haupt-Passwort ist sicher."
        break
    fi
done

# =========================
# LUKS-Passwort setzen (KLARTEXT!)
# =========================
echo ""
read -p "Separates LUKS-Passwort verwenden? (j/n) [n]: " separate_luks
if [[ $separate_luks =~ ^[JjYy] ]]; then
    while true; do
        LUKS_PASSWORD=$(read_password "LUKS-Passwort eingeben (für Festplattenverschlüsselung): ")
        LUKS_CONFIRM=$(read_password "LUKS-Passwort bestätigen: ")
        echo ""

        if [ "$LUKS_PASSWORD" != "$LUKS_CONFIRM" ]; then
            echo "❌ LUKS-Passwörter stimmen nicht überein."
            continue
        fi

        if [[ ${#LUKS_PASSWORD} -lt 8 ]]; then
            echo "❌ LUKS-Passwort muss mindestens 8 Zeichen lang sein."
            continue
        fi

        echo "✅ LUKS-Passwort gesetzt."
        break
    done
else
    # identisches Passwort wie User
    LUKS_PASSWORD="$MAIN_PASSWORD"
    echo "ℹ️  Verwende Haupt-Passwort auch für LUKS."
fi

############################
# HOST DEPENDENCIES
############################
echo "Installiere Host-Abhängigkeiten..."
sudo apt-get update
sudo apt-get install -y isolinux syslinux-common xorriso rsync wget curl gnupg tar \
    ufw tpm2-tools clevis clevis-tpm2 clevis-luks squashfs-tools snapd

############################
# CLEAN
############################
sudo rm -rf "$WORKDIR"/{iso,mnt,extras} "$ISO_OUT"
mkdir -p "$WORKDIR"/{iso,mnt,extras}

############################
# DOWNLOAD DEBIAN DVD ISO
############################
echo "Lade Debian ISO herunter..."
if [ ! -f "$WORKDIR/base.iso" ]; then
    wget -O "$WORKDIR/base.iso" "$ISO_URL"
fi

sudo mount -o loop "$WORKDIR/base.iso" "$WORKDIR/mnt"
rsync -a "$WORKDIR/mnt/" "$WORKDIR/iso/"
sudo umount "$WORKDIR/mnt"
sudo chmod -R u+w "$WORKDIR/iso"

############################
# TPM2/LUKS - AUTO SETUP (Non-Interactive)
############################
cat >"$WORKDIR/extras/tpm-luks-setup.sh" <<'TPMLUKS'
#!/bin/bash
set -e

# Configuration (can be overridden by environment variables)
TPM_LUKS_PCRS="${TPM_LUKS_PCRS:-0,1,2,4,5,7,8}"
SKIP_TPM_SETUP="${SKIP_TPM_SETUP:-false}"
FORCE_TPM_SETUP="${FORCE_TPM_SETUP:-false}"
AUTO_CONFIRM="${AUTO_CONFIRM:-true}"

# Paths
TPM_LUKS_KEY_TMP="/tmp/tpm_luks.key"
TPM_LUKS_POLICY_TMP="/tmp/tpm_luks.policy"
CRYPTDEV_NAME="cryptroot"
TPM_HANDLE="0x81000000"
BACKUP_PASSPHRASE_FILE="/root/luks-recovery.key"

log_info() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') [INFO] $1" | tee -a /var/log/install/tpm-setup.log
}

log_warning() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') [WARN] $1" | tee -a /var/log/install/tpm-setup.log
}

log_error() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') [ERROR] $1" | tee -a /var/log/install/tpm-setup.log >&2
}

cleanup_tpm() {
    log_info "Cleaning up TPM resources..."
    # Remove temporary TPM objects
    tpm2_evictcontrol -C o -c $TPM_HANDLE 2>/dev/null || true
    tpm2_flushcontext -t 2>/dev/null || true
    tpm2_flushcontext -s 2>/dev/null || true
    tpm2_flushcontext -l 2>/dev/null || true
    
    # Securely delete temporary files
    if [ -f "$TPM_LUKS_KEY_TMP" ]; then
        shred -u -z -n 3 "$TPM_LUKS_KEY_TMP"
    fi
    if [ -f "$TPM_LUKS_POLICY_TMP" ]; then
        shred -u "$TPM_LUKS_POLICY_TMP"
    fi
    rm -f primary.context pcr.bin imported_key.* 2>/dev/null || true
}

trap cleanup_tpm EXIT INT TERM

detect_luks_device() {
    log_info "Detecting LUKS device..."
    
    # Method 1: Check for root filesystem
    local root_fs=$(findmnt -n -o SOURCE / 2>/dev/null)
    if [[ "$root_fs" =~ /dev/mapper/ ]]; then
        LUKS_DEVICE=$(cryptsetup status "$root_fs" 2>/dev/null | grep "device:" | awk '{print $2}')
        if [ -n "$LUKS_DEVICE" ] && [ -e "$LUKS_DEVICE" ]; then
            log_info "Found root LUKS device: $LUKS_DEVICE"
            return 0
        fi
    fi
    
    # Method 2: Check for LUKS devices in /dev
    for i in {1..10}; do
        local luks_devices=$(lsblk -f -o NAME,FSTYPE,TYPE | awk '/crypto_LUKS/ && /disk|part/ {print "/dev/" $1}')
        
        for device in $luks_devices; do
            if cryptsetup isLuks "$device" 2>/dev/null; then
                # Check if it's the system device (contains root partition)
                if cryptsetup luksOpen --test-passphrase "$device" 2>/dev/null; then
                    LUKS_DEVICE="$device"
                    log_info "Found LUKS device: $LUKS_DEVICE"
                    return 0
                fi
            fi
        done
        sleep 1
    done
    
    # Method 3: Check crypttab
    if [ -f /etc/crypttab ]; then
        local crypttab_device=$(awk '$1 !~ /^#/ && $2 ~ /\/dev\// {print $2; exit}' /etc/crypttab)
        if [ -n "$crypttab_device" ] && cryptsetup isLuks "$crypttab_device" 2>/dev/null; then
            LUKS_DEVICE="$crypttab_device"
            log_info "Found LUKS device from crypttab: $LUKS_DEVICE"
            return 0
        fi
    fi
    
    log_error "No LUKS device found"
    return 1
}

check_tpm() {
    log_info "Checking TPM2 availability..."
    
    # Check TPM2 tools
    if ! command -v tpm2_getrandom >/dev/null 2>&1; then
        log_error "TPM2 tools not installed"
        return 1
    fi
    
    # Check TPM device
    if ! ls /dev/tpm* 2>/dev/null | grep -q tpm; then
        log_warning "TPM2 device not found in /dev/"
        
        # Try to load TPM kernel module
        modprobe tpm_tis 2>/dev/null || modprobe tpm_crb 2>/dev/null || true
        sleep 1
        
        if ! ls /dev/tpm* 2>/dev/null | grep -q tpm; then
            log_warning "TPM2 hardware not detected"
            return 1
        fi
    fi
    
    # Check TPM accessibility
    if ! tpm2_getrandom 4 >/dev/null 2>&1; then
        log_warning "TPM2 not accessible"
        
        # Check if TPM2-ABRMD service is running
        if systemctl is-active tpm2-abrmd >/dev/null 2>&1; then
            log_info "TPM2-ABRMD service is running"
        else
            systemctl start tpm2-abrmd 2>/dev/null || true
            sleep 2
        fi
        
        if ! tpm2_getrandom 4 >/dev/null 2>&1; then
            log_error "TPM2 still not accessible after service start"
            return 1
        fi
    fi
    
    # Verify TPM2.0 compliance
    if ! tpm2_getcap properties-variable 2>/dev/null | grep -q "TPM2_PT_FAMILY_INDICATOR.*2.0"; then
        log_warning "TPM is not version 2.0 compliant"
        return 1
    fi
    
    log_info "TPM2.0 detected and accessible"
    return 0
}

generate_tpm_key() {
    log_info "Generating TPM-protected key..."
    
    # Create primary key under owner hierarchy
    if ! tpm2_createprimary -C o -g sha256 -G ecc -c primary.context -Q; then
        log_error "Failed to create primary key"
        return 1
    fi
    
    # Read current PCR values
    if ! tpm2_pcrread -Q -o pcr.bin sha256:${TPM_LUKS_PCRS}; then
        log_error "Failed to read PCRs"
        return 1
    fi
    
    # Create PCR policy
    if ! tpm2_createpolicy --policy-pcr -Q -L sha256:${TPM_LUKS_PCRS} -f pcr.bin \
        -P "$TPM_LUKS_POLICY_TMP"; then
        log_error "Failed to create PCR policy"
        return 1
    fi
    
    # Generate random key (256-bit for LUKS2)
    if ! dd if=/dev/urandom bs=32 count=1 of="$TPM_LUKS_KEY_TMP" status=none; then
        log_error "Failed to generate random key"
        return 1
    fi
    
    # Import key into TPM with policy
    if ! tpm2_import -C primary.context -G aes256 -i "$TPM_LUKS_KEY_TMP" \
        -r imported_key.priv -u imported_key.pub \
        -L "$TPM_LUKS_POLICY_TMP" \
        -a "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|noda"; then
        log_error "Failed to import key into TPM"
        return 1
    fi
    
    # Load and persist key
    if ! tpm2_load -C primary.context -u imported_key.pub -r imported_key.priv \
        -c imported_key.context -Q; then
        log_error "Failed to load key into TPM"
        return 1
    fi
    
    # Evict control to persistent handle
    if ! tpm2_evictcontrol -C o -c imported_key.context $TPM_HANDLE -Q; then
        log_error "Failed to persist TPM key"
        return 1
    fi

    # Prüfe Secure Boot Status für PCR 7
    if mokutil --sb-state 2>/dev/null | grep -q "SecureBoot enabled"; then
        log_info "Secure Boot aktiv - binde PCR 7 ein"
        # PCR 7 wird automatisch durch TPM gemessen wenn Secure Boot aktiv
    else
        log_warning "Secure Boot nicht aktiv - PCR 7 kann nicht gemessen werden"
        # Option: Ohne PCR 7 fortfahren oder Warnung ausgeben
    fi
    
    log_info "TPM key generated and persisted at handle $TPM_HANDLE"
    return 0
}

add_tpm_key_to_luks() {
    log_info "Adding TPM key to LUKS..."
    
    # Determine which key slot to use
    local tpm_keyslot="${LUKS_KEYSLOT_TPM:-1}"
    
    # Check if key slot is available
    if cryptsetup luksDump "$LUKS_DEVICE" 2>/dev/null | grep -q "Key slot $tpm_keyslot: ENABLED"; then
        log_warning "LUKS key slot $tpm_keyslot already in use, trying slot 2"
        tpm_keyslot=2
    fi
    
    # Check if slot 2 is also occupied
    if cryptsetup luksDump "$LUKS_DEVICE" 2>/dev/null | grep -q "Key slot $tpm_keyslot: ENABLED"; then
        log_error "No free LUKS key slots available for TPM key"
        return 1
    fi
    
    # Add TPM key to LUKS
    if ! cryptsetup luksAddKey "$LUKS_DEVICE" "$TPM_LUKS_KEY_TMP" --key-slot "$tpm_keyslot" --pbkdf "argon2i"; then
        log_error "Failed to add TPM key to LUKS"
        return 1
    fi
    
    log_info "TPM key added to LUKS slot $tpm_keyslot"
    TPM_KEYSLOT="$tpm_keyslot"
    
    # Bind Clevis to TPM for automatic unlocking
    if command -v clevis >/dev/null 2>&1; then
        log_info "Binding Clevis to TPM..."
        if ! clevis luks bind -d "$LUKS_DEVICE" -s "$TPM_KEYSLOT" tpm2 \
            '{"pcr_bank":"sha256","pcr_ids":"'"${TPM_LUKS_PCRS}"'"}' 2>/dev/null; then
            log_warning "Clevis binding failed, but LUKS key was added"
        else
            log_info "Clevis successfully bound to TPM"
        fi
    fi
    
    return 0
}

configure_initramfs() {
    log_info "Configuring initramfs for TPM unlocking..."
    
    # Install required packages
    apt-get update && apt-get install -y clevis-tpm2 clevis-initramfs tpm2-tools dracut-network 2>/dev/null || true
    
    # Verwende vorhandenes /tmp statt tmpfs
    export TMPDIR="/tmp"
    
    # Erstelle dracut-Konfiguration nur wenn /etc/dracut.conf.d existiert
    if [ -d /etc/dracut.conf.d ]; then
        cat > /etc/dracut.conf.d/99-tpm-clevis.conf <<'EOF'
# Enable TPM and Clevis in initramfs
add_dracutmodules+=" crypt clevis "
omit_dracutmodules+=" network-legacy "
add_drivers+=" tpm tpm_tis tpm_crb "
kernel_cmdline+=" rd.luks.uuid=$(cryptsetup luksUUID "$LUKS_DEVICE" 2>/dev/null || echo "")"
EOF
    fi
    
    # Erst initramfs updaten, dann Clevis binden
    log_info "Updating initramfs..."
    
    # Option 1: update-initramfs (Debian Standard)
    if command -v update-initramfs >/dev/null 2>&1; then
        update-initramfs -u -k all 2>/dev/null || {
            log_warning "update-initramfs failed, trying alternative method..."
            # Alternative: Kernel-Version ermitteln und direkt aufrufen
            KERNEL_VERSION=$(uname -r)
            mkinitramfs -o "/boot/initrd.img-${KERNEL_VERSION}" "${KERNEL_VERSION}" 2>/dev/null || true
        }
    fi
    
    # Option 2: dracut (falls verfügbar)
    if command -v dracut >/dev/null 2>&1; then
        # Mit mehr Speicher für temporäre Dateien
        DRACUT_TMPDIR=$(mktemp -d)
        export TMPDIR="$DRACUT_TMPDIR"
        
        # Erstelle initramfs für alle Kernel
        for kernel in /lib/modules/*; do
            if [ -d "$kernel" ]; then
                kernel_version=$(basename "$kernel")
                dracut -f --kver "$kernel_version" 2>/dev/null || true
            fi
        done
        
        # Aufräumen
        rm -rf "$DRACUT_TMPDIR"
    fi
    
    # Clevis binding NACH initramfs Update
    if command -v clevis >/dev/null 2>&1 && [ -n "$LUKS_DEVICE" ]; then
        log_info "Binding Clevis to TPM..."
        if ! clevis luks bind -d "$LUKS_DEVICE" -s "$TPM_KEYSLOT" tpm2 \
            '{"pcr_bank":"sha256","pcr_ids":"'"${TPM_LUKS_PCRS}"'"}' 2>/dev/null; then
            log_warning "Clevis binding failed, but LUKS key was added"
        else
            log_info "Clevis successfully bound to TPM"
            # Nochmal initramfs aktualisieren nach Clevis binding
            update-initramfs -u -k all 2>/dev/null || true
        fi
    fi
    
    log_info "Initramfs configured for TPM unlocking"
}

create_backup_solutions() {
    log_info "Creating backup and recovery solutions..."
    
    local backup_dir="/root/luks-backup-$(date +%Y%m%d-%H%M%S)"
    mkdir -p "$backup_dir"
    chmod 700 "$backup_dir"
    
    # 1. LUKS header backup
    log_info "Creating LUKS header backup..."
    cryptsetup luksHeaderBackup "$LUKS_DEVICE" \
        --header-backup-file "$backup_dir/luks-header.bak"
    
    # 2. Generate recovery passphrase
    log_info "Generating recovery passphrase..."
    local recovery_passphrase=$(openssl rand -base64 32 | tr -dc 'A-Za-z0-9!@#$%^&*()_+-=')
    echo "$recovery_passphrase" > "$BACKUP_PASSPHRASE_FILE"
    chmod 600 "$BACKUP_PASSPHRASE_FILE"
    
    # Add recovery passphrase to LUKS (slot 7)
    log_info "Adding recovery passphrase to LUKS..."
    echo "$recovery_passphrase" | cryptsetup luksAddKey "$LUKS_DEVICE" --key-slot 7 --pbkdf "argon2i"
    
    # 3. Save TPM key (encrypted with recovery passphrase)
    if [ -f "$TPM_LUKS_KEY_TMP" ]; then
        log_info "Encrypting TPM key for backup..."
        echo "$recovery_passphrase" | openssl enc -aes-256-cbc -pbkdf2 -iter 1000000 \
            -in "$TPM_LUKS_KEY_TMP" \
            -out "$backup_dir/tpm-luks-key.enc" \
            -pass stdin
    fi
    
    log_warning "BACKUP CREATED: $backup_dir"
    log_warning "Recovery passphrase saved to: $BACKUP_PASSPHRASE_FILE"
    
    return 0
}

test_tpm_unlocking() {
    log_info "Testing TPM unlocking..."
    
    if [ -z "$TPM_KEYSLOT" ]; then
        log_error "TPM key slot not defined"
        return 1
    fi
    
    if cryptsetup luksOpen --test-passphrase --key-slot "$TPM_KEYSLOT" "$LUKS_DEVICE" 2>/dev/null; then
        log_info "✓ TPM key slot $TPM_KEYSLOT is functional"
        return 0
    else
        log_error "TPM key slot test FAILED"
        return 1
    fi
}

check_virtual_machine() {
    # Prüfe ob wir in einer VM laufen
    if [ -f /proc/cpuinfo ]; then
        if grep -qi "hypervisor\|vmware\|kvm\|virtualbox\|qemu\|xen" /proc/cpuinfo; then
            return 0  # VM erkannt
        fi
    fi
    
    # Prüfe DMI Informationen
    if [ -f /sys/class/dmi/id/sys_vendor ]; then
        local vendor=$(cat /sys/class/dmi/id/sys_vendor | tr '[:upper:]' '[:lower:]')
        if [[ "$vendor" =~ (vmware|virtualbox|qemu|kvm|xen|microsoft) ]]; then
            return 0  # VM erkannt
        fi
    fi
    
    # Prüfe systemd-detect-virt
    if command -v systemd-detect-virt >/dev/null 2>&1; then
        local virt=$(systemd-detect-virt)
        if [ "$virt" != "none" ]; then
            return 0  # VM erkannt
        fi
    fi
    
    return 1  # Keine VM erkannt
}

main_tpm_setup() {
    echo "=== TPM2/LUKS AUTO SETUP ==="
    
    # Initialize log
    mkdir -p /var/log/install
    > /var/log/install/tpm-setup.log
    
    # Check if TPM setup should be skipped
    if [ "$SKIP_TPM_SETUP" = "true" ] && [ "$FORCE_TPM_SETUP" != "true" ]; then
        log_info "TPM setup skipped (SKIP_TPM_SETUP=true)"
        echo "TPM setup skipped as requested"
        return 0
    fi
    
    # Check if running in a VM - VERBESSERTE PRÜFUNG
    if check_virtual_machine; then
        log_warning "Running in virtual machine - TPM may not be available"
        if [ "$FORCE_TPM_SETUP" != "true" ]; then
            echo "⚠️  VM detected - Skipping TPM setup (no hardware TPM available)"
            echo "Use FORCE_TPM_SETUP=true to override if using vTPM"
            return 0
        else
            log_info "VM detected but FORCE_TPM_SETUP=true, continuing..."
        fi
    fi
    
    # Step 1: Check TPM
    if ! check_tpm; then
        log_warning "TPM not available or not functional"
        echo "❌ TPM nicht verfügbar oder nicht funktionsfähig"
        echo "Skipping TPM setup"
        return 1
    fi
    
    # Step 2: Detect LUKS device
    if ! detect_luks_device; then
        log_error "Cannot proceed without LUKS device"
        return 1
    fi
    
    # Step 3: Generate TPM key
    echo "Generating TPM-protected key..."
    if ! generate_tpm_key; then
        log_error "Failed to generate TPM key"
        return 1
    fi
    
    # Step 4: Add key to LUKS
    echo "Adding TPM key to LUKS..."
    if ! add_tpm_key_to_luks; then
        log_error "Failed to add TPM key to LUKS"
        return 1
    fi
    
    # Step 5: Test unlocking
    echo "Testing TPM unlocking..."
    if ! test_tpm_unlocking; then
        log_error "TPM unlocking test failed"
        return 1
    fi
    
    # Step 6: Configure initramfs
    echo "Configuring boot environment..."
    configure_initramfs
    
    # Step 7: Create backups
    echo "Creating backup and recovery options..."
    create_backup_solutions
    
    # Cleanup
    cleanup_tpm
    
    echo
    echo "=== TPM2/LUKS SETUP COMPLETE ==="
    echo "✓ TPM key generated and persisted"
    echo "✓ LUKS configured for TPM unlocking"
    echo "✓ Recovery options created"
    echo
    echo "Backup location: /root/luks-backup-*"
    echo "Recovery passphrase: $BACKUP_PASSPHRASE_FILE"
    
    return 0
}

# Main execution
if [ "$AUTO_CONFIRM" = "true" ]; then
    echo "Auto-confirm enabled, proceeding with TPM setup..."
    main_tpm_setup
else
    # Interactive confirmation (only if AUTO_CONFIRM is false)
    echo
    echo "This script will configure TPM2 for automatic LUKS unlocking."
    echo "WARN: If TPM fails or PCRs change, you will need recovery keys!"
    echo
    read -p "Continue with TPM setup? (y/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        main_tpm_setup
    else
        echo "TPM setup cancelled"
        exit 0
    fi
fi

# Capture exit code
EXIT_CODE=$?

if [ $EXIT_CODE -eq 0 ]; then
    log_info "TPM setup completed successfully"
else
    log_error "TPM setup failed with code $EXIT_CODE"
fi

exit $EXIT_CODE
TPMLUKS

chmod +x "$WORKDIR/extras/tpm-luks-setup.sh"

############################
# Spezifische AppArmor-Profile
############################
cat >"$WORKDIR/extras/profiles.sh" <<'PROFILES'
#!/bin/bash
set -e

# ------------------------------------------------------------
# Logging-Funktionen (schreiben nur in Log-Datei)
# ------------------------------------------------------------
LOG_FILE="/var/log/install/apparmor-setup.log"
mkdir -p "$(dirname "$LOG_FILE")"

log_info() {
    printf "%s [INFO] %s\n" "$(date '+%Y-%m-%d %H:%M:%S')" "$1" >> "$LOG_FILE"
}

log_warning() {
    printf "%s [WARN] %s\n" "$(date '+%Y-%m-%d %H:%M:%S')" "$1" >> "$LOG_FILE"
}

log_error() {
    printf "%s [ERROR] %s\n" "$(date '+%Y-%m-%d %H:%M:%S')" "$1" >> "$LOG_FILE"
}

log_info "== AppArmor: Systemdienste erzwingen, Desktop ignorieren =="

# ------------------------------------------------------------
# 1. APT-PINNING FÜR UNERWÜNSCHTE DESKTOP-APPS
# ------------------------------------------------------------
log_info "Erstelle APT-Block für unerwünschte Pakete..."

cat > /etc/apt/preferences.d/99-block-unwanted <<'APTBLOCK'
Package: chromium*
Pin: release *
Pin-Priority: -1000

Package: google-chrome*
Pin: release *
Pin-Priority: -1000

Package: opera*
Pin: release *
Pin-Priority: -1000

Package: steam*
Pin: release *
Pin-Priority: -1000

Package: lutris*
Pin: release *
Pin-Priority: -1000

Package: heroic*
Pin: release *
Pin-Priority: -1000

Package: discord*
Pin: release *
Pin-Priority: -1000
APTBLOCK

log_info "  ✓ APT-Block aktiv"

# ------------------------------------------------------------
# 2. APPARMOR: NUR SYSTEMDIENSTE AUF ENFORCE SETZEN
# ------------------------------------------------------------
# Wichtig: In chroot können wir AppArmor nicht richtig verwalten
# Die Einrichtung wird in der tatsächlichen Systemumgebung durchgeführt

log_info "AppArmor wird beim ersten Systemstart konfiguriert..."

# Erstelle ein Systemd-Service für nach der Installation
cat > /etc/systemd/system/firstboot-apparmor.service <<'EOF'
[Unit]
Description=Configure AppArmor on first boot
After=apparmor.service systemd-udev-settle.service
Before=multi-user.target
ConditionPathExists=!/etc/apparmor/.firstboot_done

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/bin/configure-apparmor-firstboot
ExecStartPost=/bin/touch /etc/apparmor/.firstboot_done

[Install]
WantedBy=multi-user.target
EOF

# ------------------------------------------------------------
# 3. Firstboot-Skript erstellen
# ------------------------------------------------------------
cat > /usr/local/bin/configure-apparmor-firstboot <<'SCRIPT'
#!/bin/bash
set -e

LOG_FILE="/var/log/install/apparmor-setup.log"
mkdir -p "$(dirname "$LOG_FILE")"

log_info() {
    printf "%s [INFO] %s\n" "$(date '+%Y-%m-%d %H:%M:%S')" "$1" >> "$LOG_FILE"
}
log_warning() {
    printf "%s [WARN] %s\n" "$(date '+%Y-%m-%d %H:%M:%S')" "$1" >> "$LOG_FILE"
}
log_error() {
    printf "%s [ERROR] %s\n" "$(date '+%Y-%m-%d %H:%M:%S')" "$1" >> "$LOG_FILE"
}

log_info "== AppArmor Firstboot configuration start =="

# Warte auf AppArmor initialisierung
for i in {1..30}; do
    if systemctl is-active --quiet apparmor; then
        break
    fi
    sleep 1
done

# Warte zusätzlich, falls AppArmor gerade startet
sleep 2

# Setze Systemprofile auf enforce (nur wenn AppArmor aktiv ist)
if aa-status 2>/dev/null | grep -q "apparmor module is loaded"; then
    log_info "Setting system profiles to enforce mode..."
    
    # Erlaube Apps ohne Profile (Complain Mode)
    # Alle IDEs werden über Snap installiert und haben eigenes Confinement
    for app in /usr/bin/nautilus /usr/bin/wireshark; do
        if [ -f "$app" ]; then
            app_name=$(basename "$app")
            aa-complain "/usr/bin/$app_name" 2>/dev/null || true
            aa-complain "$app" 2>/dev/null || true
        fi
    done
    
    # Setze alle geladenen Systemprofile auf enforce
    for profile in $(aa-status 2>/dev/null | grep -E "^\s+/" | awk '{print $1}'); do
        # Überspringe bereits in complain mode gesetzte Apps
        if [[ ! "$profile" =~ (nautilus|wireshark|papers) ]]; then
            aa-enforce "$profile" 2>/dev/null || true
        fi
    done
    
    log_info "AppArmor Konfiguration abgeschlossen"
else
    log_warning "AppArmor nicht aktiv, überspringe Konfiguration"
fi
SCRIPT

chmod +x /usr/local/bin/configure-apparmor-firstboot

# Aktiviere den Firstboot-Service
systemctl enable firstboot-apparmor.service

# Alle geladenen Systemprofile auf enforce setzen
if command -v aa-status >/dev/null 2>&1 && aa-status 2>&1 | grep -q "apparmor module is loaded"; then
    log_info "Setze wichtige Systemprofile auf ENFORCE..."
    
    SYSTEM_PROFILES=(
        "usr.sbin.cupsd"
        "usr.sbin.avahi-daemon"
        "usr.sbin.nmbd"
        "usr.sbin.smbd"
        "usr.sbin.nscd"
        "usr.sbin.traceroute"
    )
    
    for profile in "${SYSTEM_PROFILES[@]}"; do
        if [ -f "/etc/apparmor.d/$profile" ]; then
            if aa-enforce "$profile" >/dev/null 2>&1; then
                log_info "  ✓ enforce: $profile"
            else
                log_warning "  ⚠️ konnte nicht erzwingen: $profile"
            fi
        fi
    done
fi

# ------------------------------------------------------------
# 4. KERNEL-PARAMETER FÜR APPARMOR
# ------------------------------------------------------------
log_info "Setze Kernel-Parameter für AppArmor..."

# Sicherstellen dass securityfs gemountet wird
if [ ! -d /sys/kernel/security ]; then
    mkdir -p /sys/kernel/security
fi

# Fstab Eintrag für securityfs
if ! grep -q "securityfs" /etc/fstab; then
    echo "securityfs /sys/kernel/security securityfs defaults 0 0" >> /etc/fstab
fi

# Kernel cmdline Parameter
if [ -d /etc/default/grub.d ]; then
    cat > /etc/default/grub.d/10-apparmor.cfg <<'GRUBAPPARMOR'
GRUB_CMDLINE_LINUX_DEFAULT="$GRUB_CMDLINE_LINUX_DEFAULT apparmor=1 security=apparmor"
GRUBAPPARMOR
else
    # Für ältere Systeme
    sed -i 's/GRUB_CMDLINE_LINUX_DEFAULT="/&apparmor=1 security=apparmor /' /etc/default/grub
fi

log_info "AppArmor setup complete."
PROFILES

chmod +x "$WORKDIR/extras/profiles.sh"

############################
# CREATE INSTALL SCRIPT
############################
cat >"$WORKDIR/extras/install.sh" <<'INSTALL'
#!/bin/bash

USERNAME="${USERNAME:-user}"
TARGET="${TARGET:-/}"
EXTRAS_DIR="/root/extras"

DESKTOP_PROFILES="$EXTRAS_DIR/profiles.sh"
TPM_SETUP_SCRIPT="$EXTRAS_DIR/tpm-luks-setup.sh"

log_info() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') [INFO] $1" | tee -a /var/log/install/setup.log
}

log_warning() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') [WARN] $1" | tee -a /var/log/install/setup.log
}

log_error() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') [ERROR] $1" | tee -a /var/log/install/setup.log >&2
}

#######################################
# SNAP INSTALLATION FÜR ALLE IDES
#######################################
log_info "=== Installiere IDEs über Snap (mit Auto-Updates) ==="

# 1. Snapd Service aktivieren
log_info "Aktiviere snapd..."
systemctl enable --now snapd.socket
systemctl start snapd.socket

# 2. Snap-Benutzer-Gruppe für Zugriff
log_info "Richte Snap-Benutzergruppe ein..."
groupadd -f snap
usermod -aG snap "$USERNAME" 2>/dev/null || log_warning "Konnte Benutzer nicht zu snap-Gruppe hinzufügen"

# 3. Systemd-Service für Snap-Installation erstellen
log_info "Erstelle Snap-Installationsservice..."

cat > /etc/systemd/system/install-snaps.service <<'EOF'
[Unit]
Description=Install JetBrains IDEs and VS Code via Snap (Community Editions)
After=network-online.target snapd.seeded
Wants=network-online.target
ConditionPathExists=!/var/lib/snapd/.ides-installed

[Service]
Type=oneshot
Environment="PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin"
# Warte bis Snapd bereit ist
ExecStartPre=/bin/bash -c 'for i in {1..30}; do snap list 2>/dev/null && break; sleep 2; done'
# Installiere VS Code (nur wenn nicht vorhanden)
ExecStart=/bin/bash -c 'if ! snap list | grep -q code; then snap install code --classic; fi'
# Installiere PyCharm Community Edition
ExecStart=/bin/bash -c 'if ! snap list | grep -q pycharm-community; then snap install pycharm-community --classic; fi'
# Installiere IntelliJ Community Edition
ExecStart=/bin/bash -c 'if ! snap list | grep -q intellij-idea-community; then snap install intellij-idea-community --classic; fi'
ExecStartPost=/bin/touch /var/lib/snapd/.ides-installed
RemainAfterExit=yes
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

# 4. Snap Auto-Update Konfiguration
log_info "Konfiguriere Snap Auto-Updates..."

cat > /etc/systemd/system/snap-auto-update.service <<'EOF'
[Unit]
Description=Auto-update Snap packages
After=network-online.target snapd.seeded
Wants=network-online.target

[Service]
Type=oneshot
Environment="PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin"
ExecStart=/usr/bin/snap refresh
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

cat > /etc/systemd/system/snap-auto-update.timer <<'EOF'
[Unit]
Description=Daily Snap auto-update
Requires=snap-auto-update.service

[Timer]
OnCalendar=daily
Persistent=true
RandomizedDelaySec=3600

[Install]
WantedBy=timers.target
EOF

# 5. Wrapper-Skripte für einfachen Zugriff
log_info "Erstelle Wrapper-Skripte für Snap-Apps..."

cat > /usr/local/bin/code <<'EOF'
#!/bin/bash
# Wrapper für VS Code Snap
if command -v code &> /dev/null; then
    /snap/bin/code "$@"
else
    echo "VS Code ist nicht installiert. Wird automatisch installiert, sobald eine Internetverbindung verfügbar ist."
    exit 1
fi
EOF

cat > /usr/local/bin/intellij <<'EOF'
#!/bin/bash
# Wrapper für IntelliJ IDEA Community Edition
if command -v intellij-idea-community &> /dev/null; then
    /snap/bin/intellij-idea-community "$@"
else
    echo "IntelliJ IDEA Community Edition ist nicht installiert. Wird automatisch installiert, sobald eine Internetverbindung verfügbar ist."
    exit 1
fi
EOF

cat > /usr/local/bin/pycharm <<'EOF'
#!/bin/bash
# Wrapper für PyCharm Community Edition
if command -v pycharm-community &> /dev/null; then
    /snap/bin/pycharm-community "$@"
else
    echo "PyCharm Community Edition ist nicht installiert. Wird automatisch installiert, sobald eine Internetverbindung verfügbar ist."
    exit 1
fi
EOF

chmod +x /usr/local/bin/code /usr/local/bin/pycharm /usr/local/bin/intellij

# 6. Services aktivieren
systemctl enable install-snaps.service
systemctl enable snap-auto-update.timer

log_info "Snap-Setup abgeschlossen. IDEs werden automatisch installiert, sobald eine Internetverbindung verfügbar ist."

#######################################
# TPM2 Setup - MIT VERBESSERTER VM-ERKENNUNG
#######################################
if [ -f "$TPM_SETUP_SCRIPT" ]; then
    log_info "=== Versuche TPM2/LUKS Einrichtung (mit VM-Check) ==="
    chmod +x "$TPM_SETUP_SCRIPT"
    
    # Prüfe zuerst ob wir in einer VM sind
    if [ -f /proc/cpuinfo ] && grep -qi "hypervisor\|vmware\|kvm\|virtualbox\|qemu\|xen" /proc/cpuinfo; then
        log_warning "VM erkannt - TPM Setup wird übersprungen (kein Hardware-TPM verfügbar)"
        echo "⚠️  VM detected - Skipping TPM setup"
    else
        "$TPM_SETUP_SCRIPT"
        TPM_EXIT_CODE=$?
        
        if [ $TPM_EXIT_CODE -eq 0 ]; then
            log_info "=> TPM2/LUKS erfolgreich eingerichtet"
        elif [ $TPM_EXIT_CODE -eq 1 ]; then
            log_warning "⚠️ TPM2 nicht verfügbar oder nicht funktionsfähig"
        else
            log_warning "⚠️ TPM2/LUKS Einrichtung fehlgeschlagen"
        fi
    fi
fi

#######################################
# Benutzer & Hostname
#######################################
cat > /etc/sudoers.d/user <<SUDO
Defaults logfile="/var/log/sudo.log"
Defaults log_input,log_output
Defaults secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
Defaults use_pty
$USERNAME ALL=(ALL) ALL
SUDO
chmod 440 /etc/sudoers.d/user

echo "$HOSTNAME" > /etc/hostname
cat > /etc/hosts <<HOSTS
127.0.0.1 localhost
127.0.1.1 $HOSTNAME.local $HOSTNAME
::1     localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
HOSTS

#######################################
# Bash Completion
#######################################
cat >> /etc/bash.bashrc <<'BASHRC'
if ! shopt -oq posix; then
  if [ -f /usr/share/bash-completion/bash_completion ]; then
    . /usr/share/bash-completion/bash_completion
  elif [ -f /etc/bash_completion ]; then
    . /etc/bash_completion
  fi
fi
BASHRC

#######################################
# Kernel Härtungen
#######################################
cat >> "$TARGET/etc/sysctl.conf" <<SYSCTL

# TPM Security
kernel.tpm.device=1
kernel.tpm.log_level=0

kernel.kptr_restrict=2
kernel.dmesg_restrict=1
fs.protected_hardlinks=1
fs.protected_symlinks=1
kernel.randomize_va_space=2

# Network
net.ipv4.conf.all.send_redirects=0
net.ipv4.conf.default.send_redirects=0
net.ipv4.conf.all.accept_local=0
net.ipv4.conf.all.shared_media=0
net.ipv4.tcp_rfc1337=1
net.ipv4.conf.all.rp_filter=1
net.ipv4.conf.default.rp_filter=1
net.ipv4.icmp_echo_ignore_broadcasts=1
net.ipv4.conf.all.accept_source_route=0
net.ipv6.conf.all.accept_source_route=0
net.ipv4.conf.all.log_martians=1
net.ipv4.tcp_syncookies=1
net.ipv4.conf.all.accept_redirects=0
net.ipv6.conf.all.accept_redirects=0
net.ipv4.tcp_timestamps=0

# IPv6
net.ipv6.conf.all.accept_redirects=0
net.ipv6.conf.default.accept_redirects=0
net.ipv6.conf.all.accept_ra=0
net.ipv6.conf.default.accept_ra=0

# Memory Hardening
kernel.yama.ptrace_scope=2
vm.mmap_min_addr=65536
kernel.unprivileged_bpf_disabled=1
net.core.bpf_jit_harden=2

# Filesystem
fs.suid_dumpable=0

SYSCTL

systemctl enable systemd-sysctl

#######################################
# TPM Systemd Service
#######################################
cat > "$TARGET/etc/systemd/system/tpm2-check.service" <<'EOF'
[Unit]
Description=Check TPM2 Status
After=tpm2-abrmd.service
ConditionPathExists=/dev/tpm0

[Service]
Type=oneshot
ExecStart=/usr/bin/tpm2_getrandom 4
ExecStartPost=/bin/bash -c 'echo "TPM2 Status: OK"'
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

systemctl enable tpm2-check.service 2>/dev/null || true

# AppArmor Konfiguration
systemctl enable apparmor

cat > "$TARGET/etc/default/grub.d/apparmor.cfg" <<GRUBAPPARMOR
GRUB_CMDLINE_LINUX_DEFAULT="\$GRUB_CMDLINE_LINUX_DEFAULT apparmor=1 security=apparmor"
GRUBAPPARMOR

if command -v update-grub >/dev/null 2>&1; then
    update-grub 2>/dev/null || echo "ℹGrub Update optional"
fi

#######################################
# SSH Hardening
#######################################
mkdir -p /etc/ssh/sshd_config.d
cat > /etc/ssh/sshd_config.d/99-hardening.conf <<'SSHDHARDEN'
PermitRootLogin no
PasswordAuthentication no
ChallengeResponseAuthentication no
UsePAM yes
X11Forwarding no
AllowTcpForwarding no
AllowAgentForwarding no
PermitEmptyPasswords no
Protocol 2
ClientAliveInterval 300
ClientAliveCountMax 2
MaxAuthTries 3
MaxSessions 2
LoginGraceTime 60
SSHDHARDEN

systemctl restart ssh

#######################################
# tmpfs Hardening
#######################################

# /tmp
mkdir -p "$TARGET/tmp"
chmod 1777 "$TARGET/tmp"

# /var/tmp
mkdir -p "$TARGET/var/tmp"
chmod 1777 "$TARGET/var/tmp"

# fstab-Einträge
cat >> "$TARGET/etc/fstab" <<'FSTAB'

#######################################
# Hardened tmpfs mounts
#######################################
tmpfs /tmp                    tmpfs defaults,nosuid,nodev,noexec,mode=1777 0 0
tmpfs /var/tmp                tmpfs defaults,nosuid,nodev,noexec,mode=1777 0 0
FSTAB

#######################################
# APT Konfiguration
#######################################
cat > "$TARGET/etc/apt/apt.conf.d/99basic" <<'APT'
APT::Install-Recommends "false";
APT::Install-Suggests "false";
APT::Get::Assume-Yes "true";
APT::Get::Force-Yes "false";
APT::Acquire::Retries "3";
APT::Update::Post-Invoke-Success {"touch /var/lib/apt/periodic/update-success-stamp 2>/dev/null || true";};
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::AutocleanInterval "7";
APT::Periodic::Unattended-Upgrade "1";
APT::NeverAutoRemove {
    "^firmware-linux";
    "^linux-firmware";
    "^linux-image-";
    "^linux-headers-";
    "^linux-modules-";
    "^kfreebsd-image-";
    "^gnumach-image-";
    "^.*-modules";
    "linux-libc-dev";
    "^busybox";
};
APT

#######################################
# Unattended Upgrades
#######################################
cat > "$TARGET/etc/apt/apt.conf.d/50unattended-upgrades" <<UNATTENDED
Unattended-Upgrade::Allowed-Origins {
    "\${distro_id}:\${distro_codename}";
    "\${distro_id}:\${distro_codename}-security";
    "\${distro_id}ESM:\${distro_codename}";
};
Unattended-Upgrade::Origins-Pattern {
    "origin=Debian,codename=\${distro_codename},label=Debian";
    "origin=Debian,codename=\${distro_codename},label=Debian-Security";
    "origin=Debian,codename=\${distro_codename}-security,label=Debian-Security";
};
Unattended-Upgrade::AutoFixInterruptedDpkg "true";
Unattended-Upgrade::MinimalSteps "true";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "false";
Unattended-Upgrade::Automatic-Reboot-Time "02:00";
UNATTENDED

#######################################
# Desktop Profile ausführen
#######################################
if [ -f "$DESKTOP_PROFILES" ]; then
    log_info "=== Führe Desktop-Profile-Skript aus ==="
    chmod +x "$DESKTOP_PROFILES"
    "$DESKTOP_PROFILES"
    log_info "=> Desktop-Profile eingerichtet"
fi

#######################################
# SUDO Logging
#######################################
cat > "$TARGET/etc/sudoers.d/99-logging" <<SUDOLOG
Defaults logfile="/var/log/sudo.log"
Defaults log_input, log_output
Defaults iolog_dir="/var/log/sudo-io/%{user}"
Defaults !tty_tickets
SUDOLOG

mkdir -p /var/log/sudo-io
chmod 0700 /var/log/sudo-io

#######################################
# auditd konfigurieren
#######################################
if command -v auditd >/dev/null 2>&1; then
    log_info "Konfiguriere auditd..."
    systemctl enable auditd 2>/dev/null || true
    
    # Erstelle die Regeln und lade sie
    if command -v augenrules >/dev/null 2>&1; then
        cat > "$TARGET/etc/audit/rules.d/hardening.rules" <<'AUDIT'
# Audit-Konfiguration schützen
-w /etc/audit/ -p wa -k audit_config

# TPM-bezogene Ereignisse
-a exit,always -F arch=b64 -S tpm -S tpm2 -k tpm_access
-a exit,always -F path=/dev/tpm0 -F perm=rwxa -k tpm_device

# Systemweite Konfiguration
-w /etc/ -p wa -k system_config

# System-Konfigurationsdateien
-w /etc/passwd -p wa -k passwd_changes
-w /etc/shadow -p wa -k shadow_changes
-w /etc/sudoers -p wa -k sudoers_changes
-w /etc/ssh/sshd_config -p wa -k ssh_changes

# LUKS/TPM Konfiguration
-w /etc/crypttab -p wa -k crypttab_changes
-w /etc/clevis -p wa -k clevis_changes

# Benutzer & Gruppen
-w /etc/passwd -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/gshadow -p wa -k identity

# sudo & Privilege Escalation
-w /etc/sudoers -p wa -k sudo
-w /etc/sudoers.d/ -p wa -k sudo

# Authentifizierung & Logs
-w /var/log/auth.log -p wa -k authlog
-w /var/log/lastlog -p wa -k logins
-w /var/run/faillock/ -p wa -k auth_failures

# Kritische Binaries
-w /usr/bin/sudo -p x -k bin_changes
-w /usr/bin/passwd -p x -k bin_changes
-w /usr/bin/su -p x -k bin_changes
-w /usr/sbin/sshd -p x -k bin_changes
-w /usr/bin/tpm2 -p x -k tpm_tools

# Zeit & Locale (Manipulationsschutz)
-w /etc/localtime -p wa -k time_change
-a always,exit -F arch=b64 -S adjtimex,settimeofday,clock_settime -k time_change

# Kernel-Module (hochrelevant!)
-w /sbin/insmod -p x -k kernel_modules
-w /sbin/rmmod -p x -k kernel_modules
-w /sbin/modprobe -p x -k kernel_modules

# Ausführung von Admin-Befehlen
-a always,exit -F arch=b64 -S execve -F euid=0 -k admin_commands

# Audit-Logs schützen
-w /var/log/audit/ -p wa -k audit_logs

# Regeländerungen selbst auditieren
-e 2
AUDIT
        augenrules --load 2>/dev/null || true
    fi
else
    log_info "auditd nicht installiert, überspringe Konfiguration"
fi

#######################################
# Secure Boot Konfiguration
#######################################
log_info "=== Konfiguriere Secure Boot ==="

# Prüfe ob UEFI
if [ -d /sys/firmware/efi ]; then
    # Installiere notwendige Pakete für Secure Boot Management
    apt-get install -y mokutil sbsigntool
    
    # Prüfe Secure Boot Status
    if mokutil --sb-state 2>/dev/null | grep -q "SecureBoot enabled"; then
        log_info "✓ Secure Boot ist im UEFI aktiviert"
        
        # TPM-PCRs für Secure Boot erweitern
        log_info "Erweitere TPM-PCRs für Secure Boot (PCR 7)..."
        export TPM_LUKS_PCRS="0,7"
        
        # MOK (Machine Owner Key) Setup
        log_info "Erstelle MOK für Kernel-Module-Signierung..."
        mkdir -p /etc/secureboot
        openssl req -new -x509 -newkey rsa:2048 \
            -keyout /etc/secureboot/MOK.key \
            -out /etc/secureboot/MOK.crt \
            -nodes -days 3650 \
            -subj "/CN=Debian Secure Boot Key/" 2>/dev/null
        
        # Wichtige Kernel-Module signieren
        for module in vfat nls_utf8 nls_cp437 tpm tpm_tis tpm_crb; do
            module_path=$(modprobe -n -v $module 2>/dev/null | grep -o "/lib/modules.*")
            if [ -f "$module_path" ]; then
                sbsign --key /etc/secureboot/MOK.key \
                       --cert /etc/secureboot/MOK.crt \
                       "$module_path" --output "$module_path.signed" 2>/dev/null && \
                mv "$module_path.signed" "$module_path"
            fi
        done
        
        # MOK importieren
        mokutil --import /etc/secureboot/MOK.crt
        
        log_info "✅ Secure Boot konfiguriert. MOK beim nächsten Boot importieren."
    else
        log_warning "⚠️ Secure Boot ist im UEFI nicht aktiviert"
        log_warning "   Bitte im UEFI/BIOS aktivieren für volle Sicherheit"
    fi
else
    log_info "System bootet nicht im UEFI-Modus - Secure Boot nicht verfügbar"
fi

#######################################
# Fail2ban
#######################################
if command -v fail2ban-server >/dev/null 2>&1; then
    log_info "Konfiguriere fail2ban..."
    
    # Stelle sicher, dass fail2ban installiert ist
    apt-get install -y fail2ban 2>/dev/null || true
    
    # Erstelle minimale funktionierende Konfiguration
    mkdir -p "$TARGET/etc/fail2ban"
    cat > "$TARGET/etc/fail2ban/jail.local" <<'F2B'
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 3
backend = systemd
action = iptables-multiport
banaction = iptables-multiport

[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
F2B
    
    # Korrekte Berechtigungen setzen
    chmod 644 "$TARGET/etc/fail2ban/jail.local"
    
    # Aktiviere den Dienst (aber starte ihn nicht im chroot)
    systemctl enable fail2ban 2>/dev/null || true
    
    log_info "fail2ban konfiguriert (wird beim Booten gestartet)"
else
    log_warning "fail2ban nicht installiert, überspringe Konfiguration"
fi

# systemd-Härtung
mkdir -p "$TARGET/etc/systemd/system.conf.d"

cat > "$TARGET/etc/systemd/system.conf.d/limits.conf" <<SYSTEMD
[Manager]
DefaultLimitCORE=0
DefaultLimitNOFILE=65535
DefaultLimitNPROC=8192
DefaultLimitMEMLOCK=0
SYSTEMD

#######################################
# Firewall (UFW)
#######################################
log_info "=== Konfiguriere UFW Firewall ==="

# Stelle sicher, dass UFW installiert ist
apt-get install -y ufw

# Deaktiviere andere Firewall-Dienste, um Konflikte zu vermeiden
systemctl stop iptables 2>/dev/null || true
systemctl stop nftables 2>/dev/null || true
systemctl stop firewalld 2>/dev/null || true
systemctl disable iptables 2>/dev/null || true
systemctl disable nftables 2>/dev/null || true
systemctl disable firewalld 2>/dev/null || true

# Setze UFW zurück (automatische Bestätigung)
echo "y" | ufw --force reset >/dev/null 2>&1

# Setze Standardrichtlinien
ufw default deny incoming
ufw default allow outgoing

# Füge notwendige Regeln hinzu
ufw allow ssh
ufw allow 53        # DNS
ufw allow 80/tcp    # HTTP
ufw allow 443/tcp   # HTTPS
ufw allow 67:68/udp # DHCP
ufw allow 123/udp   # NTP

# Aktiviere UFW (mit force flag für non-interactive)
ufw --force enable

# Aktiviere und starte den UFW-Dienst
systemctl enable ufw
systemctl start ufw

# Erstelle einen Systemd-Service, der sicherstellt, dass UFW nach jedem Boot läuft
cat > /etc/systemd/system/ufw-ensure.service << 'EOF'
[Unit]
Description=Ensure UFW is enabled and running
After=network.target
Wants=network.target

[Service]
Type=oneshot
# Prüfe, ob UFW aktiv ist, wenn nicht, aktiviere es
ExecStart=/bin/bash -c 'if ! /usr/sbin/ufw status | grep -q "Status: active"; then /usr/sbin/ufw --force enable; fi'
ExecStartPost=/bin/systemctl restart ufw
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

systemctl enable ufw-ensure.service

# Teste ob UFW aktiv ist
if ufw status | grep -q "Status: active"; then
    log_info "=> UFW erfolgreich aktiviert und gestartet"
else
    log_warning "⚠️ UFW ist nicht aktiv, versuche es manuell zu starten"
    systemctl restart ufw
    sleep 2
    if ufw status | grep -q "Status: active"; then
        log_info "=> UFW nach manuellem Start aktiv"
    else
        log_error " UFW konnte nicht gestartet werden"
    fi
fi

#######################################
# USBGuard (vollständige Konfiguration)
#######################################
if command -v usbguard >/dev/null 2>&1; then
    log_info "=== USBGuard Konfiguration ==="
    
    # 1. Stelle sicher, dass usbguard Paket vollständig installiert ist
    apt-get install --reinstall -y usbguard 2>/dev/null || true
    
    # 2. Erstelle minimale grundlegende Konfiguration
    mkdir -p /etc/usbguard
    cat > "$TARGET/etc/usbguard/usbguard-daemon.conf" <<'EOF'
# USBGuard Daemon Konfiguration - Minimal für Debian
RuleFile=/etc/usbguard/rules.conf
ImplicitPolicyTarget=block
PresentDevicePolicy=apply-policy
PresentControllerPolicy=allow
InsertedDevicePolicy=apply-policy
RestoreControllerDeviceState=false
IPCAllowedUsers=root
IPCAllowedGroups=wheel
EOF
    
    # Setze korrekte Berechtigungen (0600)
    chmod 600 "$TARGET/etc/usbguard/usbguard-daemon.conf"
    
    # 3. Erstelle einfache Regeln
    cat > "$TARGET/etc/usbguard/rules.conf" <<'EOF'
# Grundlegende USBGuard Regeln
# Erlaube alle aktuell angeschlossenen Geräte (beim ersten Start)
allow

# Standard: Blockiere alles
block

# Erlaube gängige Gerätetypen:

# 1. Tastaturen und Mäuse
allow with-interface equals {03:*:*}

# 2. USB Hubs
allow with-interface equals {09:00:*}

# 3. Massenspeicher
allow with-interface equals {08:06:50}

# 4. Netzwerkadapter
allow with-interface equals {02:*:*}

# 5. Serielle Adapter
allow with-interface equals {02:02:*}
EOF
    
    chmod 600 "$TARGET/etc/usbguard/rules.conf"
    
    # 4. Setze Besitzer auf root (wird von usbguard selbst korrigiert)
    chown root:root "$TARGET/etc/usbguard/usbguard-daemon.conf"
    chown root:root "$TARGET/etc/usbguard/rules.conf"
    
    # 5. Deaktiviere den usbguard-dbus Dienst, da wir ihn nicht verwenden
    systemctl disable usbguard-dbus.service 2>/dev/null || true
    systemctl mask usbguard-dbus.service 2>/dev/null || true
    
    # 6. Erstelle systemd Service-Datei für Policy-Anwendung
    cat > "$TARGET/etc/systemd/system/usbguard-policy.service" <<'EOF'
[Unit]
Description=Apply USBGuard Policy at first boot
After=usbguard.service
Requires=usbguard.service
ConditionPathExists=!/etc/usbguard/.policy_applied

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/bash -c 'sleep 3 && /usr/bin/usbguard set-parameter ImplicitPolicyTarget block 2>/dev/null || true'
ExecStartPost=/bin/touch /etc/usbguard/.policy_applied
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF
    
    # 7. Erstelle wheel Gruppe und füge Benutzer hinzu (falls nicht existiert)
    groupadd -f wheel
    usermod -aG wheel "$USERNAME" 2>/dev/null || true
    
    # 8. Aktiviere Dienste (aber nicht starten, da im chroot)
    systemctl enable usbguard.service
    systemctl enable usbguard-policy.service
    
    log_info "USBGuard wurde konfiguriert"
else
    log_warning "USBGuard ist nicht installiert, überspringe Konfiguration"
fi

# Limits
cat > "$TARGET/etc/security/limits.d/99-hardening.conf" <<LIMITS
*               hard    core        0
*               soft    nproc       4096
*               hard    nproc       8192
*               soft    nofile      65535
*               hard    nofile      65535
*               hard    memlock     0
LIMITS

#######################################
# Systemd Services aktivieren
#######################################
REQUIRED_SERVICES=(
    "auditd"
    "fail2ban"
    "ufw"
    "apparmor"
)

for svc in "${REQUIRED_SERVICES[@]}"; do
    if [ -f "/lib/systemd/system/${svc}.service" ] || [ -f "/etc/systemd/system/${svc}.service" ]; then
        systemctl enable "$svc" 2>/dev/null || true
    fi
done

#######################################
# Unnötige Services deaktivieren
#######################################
UNNEEDED_SERVICES=(
  avahi-daemon.service
  avahi-daemon.socket
  bluetooth.service
  bluetooth.target
  cups.service
  cups.socket
  rpcbind.service
  rpcbind.socket
)

for svc in "${UNNEEDED_SERVICES[@]}"; do
  systemctl disable "$svc" 2>/dev/null || true
  systemctl mask "$svc" 2>/dev/null || true
done

#######################################
# DOCKER Konfig
#######################################
if command -v docker >/dev/null 2>&1; then
    groupadd -f docker
    usermod -aG docker "$USERNAME" 2>/dev/null || true
fi

#######################################
# WIRESHARK Konfig
#######################################
if command -v wireshark >/dev/null 2>&1; then
    groupadd -f wireshark
    usermod -aG wireshark "$USERNAME" 2>/dev/null || true
    if [ -f "/usr/bin/dumpcap" ]; then
        setcap cap_net_raw,cap_net_admin=eip /usr/bin/dumpcap 2>/dev/null || true
    fi
fi

#######################################
# Aliase
#######################################
cat >> /etc/bash.bashrc <<'BASH_ALIAS'

# Listing
alias ll='ls -alF'
alias la='ls -A'
alias l='ls -CF'

# Snap Status
alias check-snaps='snap list && echo "---" && systemctl status install-snaps.service'
alias snap-update='sudo snap refresh'

# Update / Cleaning
alias update='sudo apt-get update && sudo apt-get upgrade -y'
alias check-updates='sudo apt-get update && apt list --upgradable 2>/dev/null | grep -v "^Listing"'
alias clean='sudo apt autoremove -y && sudo apt autoclean'

# Security
alias check-apparmor='sudo aa-status | grep -E "(profiles are loaded|profiles are in)"'
alias check-audit='sudo ausearch -m avc -ts today 2>/dev/null || echo "Keine AVC Meldungen heute"'
alias check-fail2ban='sudo fail2ban-client status 2>/dev/null || echo "Fail2ban nicht aktiv"'
alias check-ufw='sudo ufw status verbose'

# TPM / Secure-Boot
alias tpm-status='tpm2_getcap properties-fixed 2>/dev/null | grep -E "(TPM2_PT_MANUFACTURER|TPM2_PT_REVISION)" || echo "TPM2 nicht verfügbar"'
alias luks-status='cryptsetup luksDump $(lsblk -f | grep crypto_LUKS | head -1 | awk "{print \"/dev/\"\$1}") 2>/dev/null | grep -E "(Key Slot|Cipher)" || echo "LUKS nicht gefunden"'
alias secureboot-check='[ -f /sys/firmware/efi/vars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c/data ] && echo -n "Secure Boot: " && od -An -t u1 /sys/firmware/efi/vars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c/data | tr -d " " || echo "UEFI/BIOS Secure Boot nicht verfügbar"'

#####################################
# ISO 27001 – auditd Nachweise
#####################################

# Überblick (Auditor liebt das)
alias audit-summary='sudo aureport --summary'

# Administrative Befehle (Root-Aktionen)
alias audit-admin='sudo ausearch -k admin_commands | aureport --exec --summary'

# sudo-Verwendung
alias audit-sudo='sudo ausearch -k sudo | aureport --file --summary'

# Benutzer- & Gruppenänderungen
alias audit-users='sudo ausearch -k identity'

# Zeitmanipulationen
alias audit-time='sudo ausearch -k time_change'

# Kernel-Module (Rootkits, Treiber)
alias audit-kernel='sudo ausearch -k kernel_modules'

# Änderungen an Systemkonfiguration
alias audit-config='sudo ausearch -k system_config'

# Auditd-Konfigurationsänderungen
alias audit-auditd='sudo ausearch -k audit_config'

# Schutz der Audit-Logs
alias audit-logs='sudo ausearch -k audit_logs'

# Fehlgeschlagene Authentifizierungen
alias audit-authfail='sudo ausearch -k auth_failures'

# Letzte 50 sicherheitsrelevante Events (live-nah)
alias audit-last='sudo ausearch -ts recent | tail -n 50'

BASH_ALIAS

# Entferne temporäre Setup-Dateien
rm -f /root/install.sh 2>/dev/null || true
rm -rf /root/extras 2>/dev/null || true

echo ""
echo "=> Installation & Härtung abgeschlossen: $(date)"
echo "Hinweis: VS Code, PyCharm und IntelliJ werden automatisch installiert,"
echo "sobald eine Internetverbindung verfügbar ist."
INSTALL

chmod +x "$WORKDIR/extras/install.sh"

############################
# COPY ALL FILES TO ISO DIRECTORY
############################
mkdir -p "$WORKDIR/iso/extras"
cp "$WORKDIR/extras/"* "$WORKDIR/iso/extras/"

############################
# NETWORK CONFIG
############################
if [ "$NETWORK_TYPE" = "dhcp" ]; then
    NETWORK_CONFIG=$(
        cat <<EOF
d-i netcfg/choose_interface select auto
d-i netcfg/get_hostname string $HOSTNAME
d-i netcfg/get_domain string $DOMAIN
d-i netcfg/dhcp_timeout string 60
EOF
    )
else
    NETWORK_CONFIG=""
fi

############################
# PRESEED – überarbeitet
############################
cat >"$WORKDIR/iso/preseed.cfg" <<PRESEED
############################
# DEBIAN 13 – UEFI
# LUKS + LVM + swap + /home
############################

### ======================
### Locale / Keyboard
### ======================
d-i debian-installer/locale string de_DE.UTF-8
d-i keyboard-configuration/xkb-keymap select de
d-i console-setup/ask_detect boolean false

### ======================
### Netzwerk
### ======================
$NETWORK_CONFIG
d-i hw-detect/load_firmware boolean true

### ======================
### Benutzer
### ======================
d-i passwd/root-login boolean false
d-i passwd/make-user boolean true
d-i passwd/user-fullname string Debian User
d-i passwd/username string $USERNAME
d-i passwd/user-password password $MAIN_PASSWORD
d-i passwd/user-password-again password $MAIN_PASSWORD
d-i user-setup/allow-password-weak boolean true
d-i user-setup/encrypt-home boolean false

### ======================
### Zeit
### ======================
d-i time/zone string Europe/Berlin
d-i clock-setup/utc boolean true
d-i clock-setup/ntp boolean true

### ======================
### Mirror
### ======================
d-i mirror/country string manual
d-i mirror/http/hostname string ftp.de.debian.org
d-i mirror/http/directory string /debian

### ==================================================
### PARTITIONIERUNG – UEFI + LUKS + LVM
### ==================================================
d-i partman-auto/disk string /dev/sda
d-i partman-auto/method string crypto
d-i partman-auto/choose_recipe select luks-lvm

# Cleanup
d-i partman-md/device_remove_md boolean true
d-i partman-lvm/device_remove_lvm boolean true
d-i partman-lvm/confirm boolean true
d-i partman-lvm/confirm_nooverwrite boolean true

### ---------- EXPERT RECIPE ----------
d-i partman-auto/expert_recipe string \
luks-lvm :: \
  512 512 512 fat32 \
    \$primary{ } \
    method{ efi } \
    format{ } \
    mountpoint{ /boot/efi } \
  . \
  1024 1024 1024 ext4 \
    \$primary{ } \
    method{ format } \
    format{ } \
    use_filesystem{ } \
    filesystem{ ext4 } \
    mountpoint{ /boot } \
  . \
  1 1 -1 crypto \
    method{ crypto } \
  . \
  lvm \
    vg_name{ debian-vg } \
    method{ lvm } \
  . \
  2048 2048 2048 linux-swap \
    lv_name{ swap } \
    method{ swap } \
    format{ } \
  . \
  20480 30480 -1 ext4 \
    lv_name{ root } \
    method{ format } \
    format{ } \
    use_filesystem{ } \
    filesystem{ ext4 } \
    mountpoint{ / } \
  . \
  10240 10240 10240 ext4 \
    lv_name{ home } \
    method{ format } \
    format{ } \
    use_filesystem{ } \
    filesystem{ ext4 } \
    mountpoint{ /home } \
  .

### ======================
### LUKS
### ======================
d-i partman-crypto/passphrase password $LUKS_PASSWORD
d-i partman-crypto/passphrase-again password $LUKS_PASSWORD
d-i partman-crypto/erase_disks boolean false

### ======================
### Bestätigungen
### ======================
d-i partman-partitioning/confirm_write_new_label boolean true
d-i partman/choose_partition select finish
d-i partman/confirm boolean true
d-i partman/confirm_nooverwrite boolean true
d-i partman-crypto/confirm boolean true
d-i partman-crypto/confirm_nooverwrite boolean true

### ======================
### Bootloader (UEFI)
### ======================
d-i grub-installer/only_debian boolean true
d-i grub-installer/with_other_os boolean false
d-i grub-installer/bootdev string default
d-i grub-installer/force-efi-extra-removable boolean true

### ======================
### Pakete
### ======================
d-i base-installer/install-recommends boolean false
tasksel tasksel/first multiselect standard ssh-server

d-i pkgsel/include string \
cryptsetup cryptsetup-initramfs lvm2 initramfs-tools \
sudo ca-certificates gnupg \
network-manager network-manager-gnome \
openssh-server git wget curl vim bash-completion command-not-found \
apparmor apparmor-utils apparmor-profiles apparmor-profiles-extra \
debsums unattended-upgrades aide aide-common \
build-essential cmake ninja-build pkg-config \
clang lld lldb gdb strace ltrace \
jq shellcheck shfmt httpie \
wireshark tcpdump nmap ufw nftables fail2ban auditd usbguard dbus \
tpm2-tools \
python3 python3-dev python3-pip python3-venv pipx \
docker.io docker-compose docker-buildx docker-cli \
default-jre \
xdg-desktop-portal xdg-desktop-portal-gnome \
snapd \
gnome-core gdm3 gnome-terminal gnome-control-center gnome-tweaks \
gnome-shell-extension-manager \
gnome-shell-extension-dash-to-dock \
xwayland wayland-protocols \
htop btop putty cups papers ptyxis firefox-esr shortwave

d-i pkgsel/upgrade select safe-upgrade
d-i pkgsel/install-language-support boolean false

### ======================
### UEFI Pakete
### ======================
d-i pkgsel/include/uefi string grub-efi-amd64-signed shim-signed efibootmgr

### ======================
### Abschluss
### ======================
d-i debconf/priority string critical
d-i preseed/interactive boolean false
d-i finish-install/reboot_in_progress note
unset MAIN_PASSWORD MAIN_CONFIRM LUKS_PASSWORD LUKS_CONFIRM

### ======================
### Late Command – robust
### ======================
d-i preseed/late_command string \
mkdir -p /target/root/extras /target/root/logs; \
cp -r /cdrom/extras/* /target/root/extras/ 2>/target/root/logs/copy.log || true; \
if [ -f /target/root/extras/install.sh ]; then \
  mv /target/root/extras/install.sh /target/root/install.sh; \
  chmod +x /target/root/install.sh; \
  in-target mkdir -p /var/log/install; \
  in-target groupadd -f sudo; \
  in-target groupadd -f plugdev; \
  in-target groupadd -f netdev; \
  in-target groupadd -f scanner; \
  in-target groupadd -f lpadmin; \
  in-target sh -c "USERNAME='$USERNAME' /root/install.sh 2>&1 | tee /var/log/install/install.log"; \
  in-target sed -i 's/^#WaylandEnable=false/WaylandEnable=true/' /etc/gdm3/daemon.conf; \
fi; \
rm -rf /target/root/extras/; \
in-target update-initramfs -u -k all; \
in-target update-grub; \
in-target apt-get clean; \
in-target apt-get autoremove -y; \
in-target chage -m 1 -M 180 -W 14 $USERNAME
PRESEED

############################
# BOOT CONFIG MIT UEFI/BIOS SUPPORT
############################
cat >"$WORKDIR/iso/isolinux/txt.cfg" <<ISOLINUX
default install
label install
  menu label ^Automated Install with GNOME, TPM2 & LUKS (Hardened)
  menu default
  kernel /install.amd/vmlinuz
  append auto=true priority=critical vga=788 initrd=/install.amd/initrd.gz preseed/file=/cdrom/preseed.cfg console-keymaps-at/keymap=de debconf/priority=critical --- quiet
label install64
  menu label ^Automated Install (64-bit)
  kernel /install.amd/vmlinuz
  append vga=788 initrd=/install.amd/initrd.gz --- quiet
ISOLINUX

# Grub Konfiguration für UEFI/BIOS
cat >"$WORKDIR/iso/boot/grub/grub.cfg" <<GRUB
set timeout=3
set default=0

menuentry "Debian Automated Install with GNOME, TPM2 & LUKS (Hardened)" {
  linux /install.amd/vmlinuz auto=true priority=critical vga=788 preseed/file=/cdrom/preseed.cfg console-keymaps-at/keymap=de debconf/priority=critical --- quiet
  initrd /install.amd/initrd.gz
}

menuentry "Debian Installer (64-bit)" {
  linux /install.amd/vmlinuz --- quiet
  initrd /install.amd/initrd.gz
}
GRUB

############################
# BUILD HYBRID ISO FÜR UEFI/BIOS
############################
ISOHDPFX=$(find /usr/lib/ISOLINUX -name isohdpfx.bin 2>/dev/null | head -n1)
[ -z "$ISOHDPFX" ] && ISOHDPFX=$(find /usr/share/syslinux -name isohdpfx.bin 2>/dev/null | head -n1)
[ -z "$ISOHDPFX" ] && {
    echo "❌ isohdpfx.bin nicht gefunden"
    exit 1
}

VOLUME_ID="DEBIAN_SECURE_APPS"

echo "Erstelle Hybrid ISO..."
xorriso -as mkisofs \
    -r -V "$VOLUME_ID" -o "$ISO_OUT" \
    -J -joliet-long -iso-level 3 \
    -partition_offset 16 \
    -isohybrid-mbr "$ISOHDPFX" \
    -b isolinux/isolinux.bin -c isolinux/boot.cat \
    -boot-load-size 4 -boot-info-table -no-emul-boot \
    -eltorito-alt-boot \
    -e boot/grub/efi.img \
    -no-emul-boot \
    -isohybrid-gpt-basdat \
    -isohybrid-apm-hfsplus \
    "$WORKDIR/iso"

############################
# FINAL MESSAGE
############################
if [ -f "$ISO_OUT" ]; then
    echo ""
    echo "=> HYBRID ISO erfolgreich erstellt: $(realpath "$ISO_OUT")"
    echo ""
    echo "=== WICHTIGE INFORMATIONEN ==="
    echo "1. ISO unterstützt UEFI und BIOS Boot"
    echo "2. Automatische Partitionserkennung:"
    echo "   - UEFI: GPT mit ESP (/boot/efi)"
    echo ""
    echo "=== SICHERHEITSFUNKTIONEN ==="
    echo "• TPM2 für LUKS-Entschlüsselung (nur auf Hardware mit TPM)"
    echo "• Secure Boot unterstützt"
    echo "• Vollständige Festplattenverschlüsselung (LUKS)"
    echo "• Automatische Sicherheits-Updates"
    echo "• Firewall (UFW) vorkonfiguriert"
    echo "• SSH-Härtung"
    echo "• APPARMOR"
    echo "• USB-Guard"
    echo ""
    echo "=== Software Post-Installation ==="
    echo "• IntelliJ: via Snap (automatische Updates)"
    echo "• PyCharm: via Snap (automatische Updates)"
    echo "• VS Code: via Snap (automatische Updates)"
    echo ""
    echo "=== INSTALLATION ==="
    echo "1a). ISO auf USB-Stick"
    echo "    • z.B. mit Rufus"
    echo "1b). VMware-Alternative:"
    echo "    • VM mit TPM-Modul"
    echo "    • Verschlüsselung aktivieren"
    echo "2. Secure Boot im UEFI aktivieren (empfohlen)"
    echo "3. Automatische Installation starten"
    echo ""
    echo "=== NACH DER INSTALLATION ==="
    echo "• Internetverbindung notwendig für Software Post-Installation"
    echo "• AppArmor-Status prüfen: aa-status"
    echo "• Snap-Status prüfen: snap list"
    echo "• Updates: sudo apt-get update && sudo apt-get upgrade"
else
    echo "❌ ISO-Erstellung fehlgeschlagen"
    exit 1
fi
