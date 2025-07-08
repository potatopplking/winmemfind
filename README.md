# Winmemfind

Simple tool that helps find given byte arrays (numbers) in windows process memory. Almost entirely vibe coded, so blame Microsoft if it crashes together with attached process and your whole OS.

## Build

Built with Visual Studio 2022, CMake hopefully should make it more versatile, did not test that.

## Usage

First scan for the byte sequence you want to find in memory (hex, no "0x" prefix):

```
scan fe 01
```

This will take some time and return large number of candidates. Then you can filter those candidates (assuming you know how the byte sequence has changed - e.g. some in-game value was incremented by 1):

```
filter ff 01
```

When you eventually narrow it down to one candidate, you can modify the value with `write` command. You can also read with `read` and manually add candidates with `add`.


## Game address notes

Observed addresses in my case. May change in-between game starts, loads, etc - whenever memory is re-allocated.

### Fallout 2

Process ID: 19524
Char points: 0x518538
Tag skills: 0x570a10

```
0: 0x9ae3662
1: 0xd2bfbd3
```

XP: 0x6681b4 (LSB)
0x6681b5
0x6681b6

skill points during level up:
0x6681ac

## Deus Ex Revision

skillpoints when creating character:

0x167099bc (LSB)
0x167099bd

## Deus Ex: Human Revolution

Changes between the saves

## Credits

0x1fb68e40 (LSB)
0x1fb68e41

## XP

0x1d471e8c (LSB)
0x1d471e8d
