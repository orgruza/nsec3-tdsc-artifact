# Data Viewer

This folder collects the measurement data of the resolver evaluation.

It comes with a viewer binary that implements a TUI interface to view the data interactively.

Demo:

<video width="auto" height="auto" controls>
  <source src="./demo.mp4" type="video/mp4">
</video>

## Usage

The viewer is a compiled executable for x86 Linux systems. 
Add executable permissions and start the viewer in a terminal that supports [Ratatui](https://ratatui.rs/), either by running the Ubuntu 24.04 compiled

```
$ ./viewer
```

or the musl-libc version that does not require any specific glibc:

```
$ ./viewer-musl
```

### Navigating in the viewer

The viewer provides a command line at the bottom of the window and features two tabs: Monitor and Log.

Keymap instructions are always visible at the bottom, full output is provided to the Log.

The command line can be entered by pressing the `Return/Enter ↵` key, typing a command, and pressing `Return/Enter ↵` again to run the typed command.

With `Tab ⇥` or `Shift + Tab ⇤`, one can switch between the Monitor and Log tabs.

The application can be exited at any point by repeatedly pressing `Esc`.

### Help

To see a list of available commands, navigate to the Log tab, enter the command line through the Return key and type `help` into the command line and press Return again.
This prints a list of the available commands.

### Viewing measurements

Use the `show [subfolder]` command to visualize any measurement located in the `measurements/` folder.

For instance, to open `1min-8x12.5rps-50iter-benign-2026-06-20T21:33:37`, type:

```
┌Command Line────────────────────────────────────────────────┐
│ show 1min-8x12.5rps-50iter-benign-2026-06-20T21:33:37      │
└────────────────────────────────────────────────────────────┘
```

Then proceed using the arrow keys to navigate in the different visualized graphs.

# Additional Figures

We provide pre-rendered visualizations of per-resolver measurements in the `figures/` folder.

## Complete measurement dataset

The complete resolver benchmark dataset is distributed through
the GitHub Releases page of this repository:

https://github.com/orgruza/nsec3-tdsc-artifact/releases

Download the following files:

- `benchmark-data.tar.gz`
- `benchmark-data.tar.gz.sha256`

Verify the archive:

```bash
sha256sum -c benchmark-data.tar.gz.sha256
```

Extract it:

```bash
tar -xzf benchmark-data.tar.gz
```

The archive extracts into `benchmark-data/` and includes the
`measurements/` directory containing the original experiment data.

The measurement data are distributed separately from the Git
repository to keep the repository lightweight.
