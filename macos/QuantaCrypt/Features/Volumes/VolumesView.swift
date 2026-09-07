import SwiftUI

struct VolumesView: View {
    @Bindable var model: VolumesModel
    @FocusState private var focus: Field?

    enum Field: Hashable {
        case createName, createPassword, createConfirmation
        case mountPoint, mountPassword, mountShare(Int)
    }

    var body: some View {
        Form {
            if let fuse = model.fuse, !fuse.ok {
                setupSection(fuse)
            } else if let error = model.fuseError {
                Section("Disk mounting") { ErrorPanel(error: error) }
            }
            // Daily task first. Creating a volume happens once per
            // volume; mounting one happens every day, and "what is open
            // right now" is the question this screen should answer first.
            mountedSection
            mountSection
            createSection
        }
        .formStyle(.grouped)
        .task { await model.pollMounted() }
        .toolbar {
            // One stable action. It used to swap between Create and Mount
            // depending on which field last held focus, silently re-arming
            // ⌘↩ to a different operation with nothing on screen saying so.
            ToolbarItem(placement: .primaryAction) {
                Button("Mount volume", systemImage: "externaldrive.badge.checkmark", action: model.mount)
                    // Not `.borderedProminent`: macOS 26 renders a disabled
                    // prominent toolbar button at full saturation, so it reads
                    // as live. The prominent copy is the inline one, which
                    // dims correctly.
                    .labelStyle(.titleAndIcon)
                    .keyboardShortcut(.return, modifiers: .command)
                    .disabled(!model.canMountNow)
                    .help(model.mountBlockedMessage ?? "Unlock and mount the volume (⌘↩)")
            }
        }
        .onChange(of: outcome) { _, new in
            if let new { AccessibilityNotification.Announcement(new).post() }
        }
        .sheet(item: $model.sharesToShow) { presentation in
            SharesSheet(shares: presentation.shares, context: presentation.context,
                        onDismiss: model.sharesSheetDismissed,
                        onSaved: { model.sharesSaved = true })
        }
        .confirmationDialog("Mount the new volume now?", isPresented: $model.offerMountAfterCreate, titleVisibility: .visible) {
            Button("Mount volume now", action: model.mountCreatedVolume)
            Button("Not now", role: .cancel) {}
        } message: {
            Text("\(model.createResult.map { Format.fileName($0.path) } ?? "The volume") was created. Mount it to start adding files.")
        }
        .confirmationDialog("Unmount \(model.unmountCandidate?.name ?? "volume")?",
                            isPresented: Binding(get: { model.unmountCandidate != nil },
                                                 set: { if !$0 { model.unmountCandidate = nil } }),
                            titleVisibility: .visible, presenting: model.unmountCandidate) { volume in
            Button("Unmount", role: .destructive) { model.unmount(volume) }
            Button("Keep mounted", role: .cancel) {}
        } message: { volume in
            Text("Anything still open from \(Format.tildePath(volume.mountPoint)) may lose unsaved work.")
        }
        .alert("This volume may have been altered",
               isPresented: Binding(get: { model.suspiciousMount != nil },
                                    set: { if !$0 { model.suspiciousMount = nil } }),
               presenting: model.suspiciousMount) { mount in
            Button("Unmount now", role: .destructive) { model.unmount(mount.volume) }
            Button("Keep mounted", role: .cancel) {}
        } message: { mount in
            Text(VolumesModel.suspiciousMountMessage(mount))
        }
    }

    private var outcome: String? {
        if let error = model.mountError { return error.message }
        if let error = model.createError { return error.message }
        if let error = model.unmountError { return error.message }
        if let note = model.mountedNote { return note }
        if let result = model.createResult, !model.createRunning {
            return "Created \(Format.fileName(result.path))."
        }
        return nil
    }

    // MARK: Setup

    private func setupSection(_ fuse: FuseCheck) -> some View {
        Section("Set up disk mounting") {
            Text("Mounting a volume as a drive needs one extra component. Creating volumes works without it.")
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            componentRow("Disk mounting support (macFUSE or FUSE-T)", fuse.fuseBackend)
            componentRow("Mounting helper", fuse.fusepy)
            Text("Install it with Homebrew, a package manager you run in Terminal. If you don't have Homebrew, get it from brew.sh first.")
                .font(.callout)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            LabeledContent("Paste this in Terminal") {
                HStack {
                    Text(VolumesModel.brewCommand)
                        .font(.body.monospaced())
                        .textSelection(.enabled)
                        .accessibilityLabel("Homebrew install command")
                        .accessibilityValue(VolumesModel.brewCommand)
                    Button("Copy") { Clipboard.copy(VolumesModel.brewCommand, expiring: false) }
                        .controlSize(.small)
                        .accessibilityLabel("Copy Homebrew install command")
                    Button("Open Terminal") { Finder.openTerminal() }
                        .controlSize(.small)
                }
            }
            Text("It will ask for your Mac's administrator password. FUSE-T is the recommended choice. If you already have macFUSE, that works too; QuantaCrypt uses whichever it finds.")
                .font(.callout)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            HStack {
                Button("Check again") {
                    Task { await model.checkFuse(userInitiated: true) }
                }
                .disabled(model.fuseChecking)
                if model.fuseChecking {
                    ProgressView().controlSize(.small)
                } else if let note = model.fuseCheckNote {
                    Text(note)
                        .font(.callout)
                        .foregroundStyle(.secondary)
                }
            }
        }
    }

    private func componentRow(_ title: String, _ component: FuseCheck.Component) -> some View {
        LabeledContent {
            Text(component.detail)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.trailing)
        } label: {
            Label(title, systemImage: component.ok ? "checkmark.circle.fill" : "xmark.circle")
                .foregroundStyle(component.ok ? Color.green : Color.primary)
        }
    }

    // MARK: Create

    private var createSection: some View {
        Section("Create a volume") {
            Text("A volume is one file that opens as a drive. Files you drag in are encrypted as they are saved; unmount it and everything is sealed back inside the .qcv file.")
                .font(.callout)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            TextField("Name", text: $model.createName)
                .focused($focus, equals: .createName)
            LabeledContent("Location") {
                HStack {
                    Text(Format.tildePath(model.createDirectory))
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                        .truncationMode(.middle)
                    Button("Change…", action: model.chooseCreateLocation)
                        .accessibilityLabel("Change where the new volume is saved")
                }
            }
            Picker("Protect with", selection: $model.createMode) {
                ForEach(ProtectionMode.allCases) { Text($0.rawValue).tag($0) }
            }
            .pickerStyle(.segmented)
            switch model.createMode {
            case .password:
                SecureField("Password", text: $model.createPassword)
                    .textContentType(.newPassword)
                    .focused($focus, equals: .createPassword)
                SecureField("Confirm password", text: $model.createConfirmation)
                    .textContentType(.newPassword)
                    .focused($focus, equals: .createConfirmation)
                    .onSubmit(model.createVolume)
                strengthRow
                WarningStrip(text: "If you forget this password the volume is gone. QuantaCrypt cannot recover it, and neither can anyone else.")
            case .splitKey:
                SplitKeyFields(threshold: $model.createThreshold, total: $model.createTotal)
            }
            Text("The volume grows as you add files, so there's no fixed size to choose.")
                .font(.callout)
                .foregroundStyle(.secondary)
            if model.fuse != nil && !model.mountingAvailable {
                WarningStrip(text: "You can create this volume now, but it can't be mounted on this Mac until disk mounting support is installed.")
            }
            if model.createRunning {
                ProgressPanel(progress: model.createProgress, isCancelling: model.createCancelling,
                              onCancel: model.cancelCreate)
            } else {
                // Unconditional: the message was hidden while the Name field
                // was empty, which is exactly when "Give the volume a name."
                // is the thing the user needs to read.
                PrimaryActionRow(title: "Create volume", systemImage: "externaldrive.badge.plus",
                                 isEnabled: model.canCreate, blockedReason: model.createValidationMessage,
                                 action: model.createVolume)
            }
            if let error = model.createError { ErrorPanel(error: error) }
            if let status = model.createStatus { StatusNote(text: status) }
            if let result = model.createResult, !model.createRunning {
                HStack {
                    Label("Created \(Format.fileName(result.path))", systemImage: "checkmark.circle.fill")
                        .foregroundStyle(.green)
                    Button("Show in Finder") { Finder.reveal(result.path) }
                    // Without this, one click on "Discard shares" sealed the
                    // volume forever; .qcx has had the same escape all along.
                    if model.canShowSharesAgain {
                        Button("Show shares again", action: model.showSharesAgain)
                    }
                    Button("Mount volume now", action: model.mountCreatedVolume)
                        .disabled(!model.mountingAvailable)
                }
            }
        }
    }

    @ViewBuilder
    private var strengthRow: some View {
        let strength = PasswordStrength.estimate(model.createPassword)
        if strength.level != .empty {
            LabeledContent("Strength") {
                HStack(spacing: 8) {
                    ProgressView(value: Double(strength.level.rawValue), total: 4)
                        .tint(strength.level >= .good ? .green : (strength.level == .fair ? .orange : .red))
                        // Not a fixed width: at accessibility text sizes the
                        // label beside it needs the room more than the meter.
                        .frame(minWidth: 80, idealWidth: 120)
                    Text(strength.advice ?? strength.level.label)
                        .font(.callout)
                        .foregroundStyle(.secondary)
                }
            }
        }
        if !model.createConfirmation.isEmpty && model.createConfirmation != model.createPassword {
            Text("The two passwords don't match.")
                .font(.callout)
                .foregroundStyle(.red)
        }
    }

    // MARK: Mount

    private var mountSection: some View {
        Section("Mount a volume") {
            if let path = model.mountPath {
                PathRow(path: path, detail: model.mountInfo?.protectionSummary,
                        systemImage: "externaldrive",
                        changeTitle: "Change…", changeLabel: "Change the volume to open",
                        onChange: model.chooseVolumeToMount)
            } else {
                DropZone(title: "Drop a volume here",
                         subtitle: "Volumes end in .qcv.",
                         systemImage: "externaldrive.badge.plus",
                         chooseTitle: "Choose volume…",
                         onChoose: model.chooseVolumeToMount,
                         accepts: VolumesModel.accepts,
                         onDrop: { model.prepareMount(path: $0.path) })
            }
            if model.mountPath != nil {
                if let info = model.mountInfo {
                    Text(info.protectionSummary)
                        .font(.callout)
                        .foregroundStyle(.secondary)
                }
                // Read-only text plus a picker, matching the Location row on
                // the create form. A free-text filesystem path existed mainly
                // to produce the "choose a folder inside your home folder"
                // error that the picker cannot produce.
                LabeledContent("Opens as a drive at") {
                    HStack {
                        Text(Format.tildePath(model.mountPoint))
                            .foregroundStyle(.secondary)
                            .lineLimit(1)
                            .truncationMode(.middle)
                            .textSelection(.enabled)
                            .accessibilityLabel("Opens as a drive at")
                            .accessibilityValue(Format.tildePath(model.mountPoint))
                        Button("Change…", action: model.chooseMountPoint)
                            .accessibilityLabel("Change where the volume appears")
                    }
                }
                if model.mountInspecting {
                    HStack(spacing: 8) {
                        ProgressView().controlSize(.small)
                        Text("Reading the volume…")
                            .font(.callout)
                            .foregroundStyle(.secondary)
                    }
                    .accessibilityElement(children: .combine)
                }
                if let error = model.mountInspectError {
                    ErrorPanel(error: error)
                    // Without this the only way back from a failed or timed-out
                    // inspect is to pick the same file again.
                    Button("Try again", action: model.retryInspect)
                        .disabled(model.mountInspecting)
                }
                // The auth block says how the volume is protected; the picker
                // is only a fallback when it could not be read.
                if model.mountInfo == nil && !model.mountInspecting {
                    Picker("Unlock with", selection: $model.mountCredential) {
                        ForEach(VolumesModel.MountCredential.allCases) { Text($0.rawValue).tag($0) }
                    }
                    .pickerStyle(.segmented)
                }
                switch model.mountCredential {
                case .password:
                    SecureField("Password", text: $model.mountPassword)
                        .textContentType(.password)
                        .focused($focus, equals: .mountPassword)
                        .onSubmit(model.mount)
                case .shares:
                    ShareEntryFields(shares: $model.mountShares, required: model.mountInfo?.threshold,
                                     total: model.mountInfo?.total, onLoadFiles: model.loadMountSharesFromFiles)
                }
                if model.fuse != nil && !model.mountingAvailable {
                    WarningStrip(text: "Install disk mounting support above before mounting.")
                }
                if model.mountRunning {
                    ProgressPanel(progress: model.mountProgress, isCancelling: model.mountCancelling,
                                  onCancel: model.cancelMount)
                } else {
                    PrimaryActionRow(title: "Mount volume", systemImage: "externaldrive.badge.checkmark",
                                     isEnabled: model.canMountNow, blockedReason: model.mountBlockedMessage,
                                     action: model.mount)
                }
            }
            if let error = model.mountError { ErrorPanel(error: error) }
            if let status = model.mountStatus { StatusNote(text: status) }
            if let note = model.mountedNote {
                Label(note, systemImage: "checkmark.circle.fill")
                    .foregroundStyle(.green)
                if model.mountedReadOnly {
                    // Not the drag-in hint: Finder would refuse the drop.
                    WarningStrip(text: VolumesModel.readOnlyMountMessage)
                } else {
                    Text("Drag files onto the drive in Finder to add them. They are encrypted as they are written, and sealed back into the volume file when you unmount.")
                        .font(.callout)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
        }
    }

    // MARK: Mounted

    private var mountedSection: some View {
        Section("Mounted volumes") {
            if let error = model.unmountError { ErrorPanel(error: error) }
            if model.listIsStale {
                WarningStrip(text: "Can't reach the helper, so this list may be out of date.")
            }
            if model.mounted.isEmpty {
                if model.listLoaded {
                    Text("No volumes are open. Choose a volume below and unlock it. It appears in Finder as a drive until you unmount it.")
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                } else {
                    Text("Checking…").foregroundStyle(.secondary)
                }
            }
            ForEach(model.mounted) { volume in
                HStack {
                    Label {
                        VStack(alignment: .leading, spacing: 2) {
                            HStack(spacing: 6) {
                                Text(volume.name)
                                    .font(.body.weight(.medium))
                                if volume.readOnly {
                                    // Same amber as WarningStrip: a drive that
                                    // refuses writes is a condition to know
                                    // about before dragging anything onto it.
                                    Label("Read-only", systemImage: "lock")
                                        .font(.callout)
                                        .foregroundStyle(.orange)
                                        .help(VolumesModel.readOnlyMountMessage)
                                }
                            }
                            Text(volumeDetail(volume))
                                .font(.callout)
                                .foregroundStyle(.secondary)
                                .lineLimit(1)
                                .truncationMode(.middle)
                        }
                    } icon: {
                        Image(systemName: "externaldrive.fill.badge.checkmark")
                            .foregroundStyle(.secondary)
                    }
                    Spacer()
                    if model.unmounting.contains(volume.mountPoint) {
                        ProgressView().controlSize(.small)
                        Text("Unmounting…").foregroundStyle(.secondary)
                    } else {
                        Button("Show in Finder") { Finder.open(volume.mountPoint) }
                            .disabled(model.listIsStale)
                            .accessibilityLabel("Show \(volume.name) in Finder")
                        Button("Unmount") { model.requestUnmount(volume) }
                            .disabled(model.listIsStale)
                            .accessibilityLabel("Unmount \(volume.name)")
                    }
                }
            }
        }
    }

    private func volumeDetail(_ volume: MountedVolume) -> String {
        var parts = [Format.tildePath(volume.mountPoint)]
        if let stats = volume.stats, let files = stats.fileCount {
            parts.append("\(files) file\(files == 1 ? "" : "s")")
            if let size = stats.totalPlaintextSize { parts.append(Format.bytes(size)) }
        }
        return parts.joined(separator: " · ")
    }
}
