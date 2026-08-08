# compare_bink.py - 对比候选 binkw32 与 Enclave 原版导出集
import struct, os

ENCLAVE_EXPORTS = [
    '_BinkBufferBlit@12','_BinkBufferCheckWinPos@12','_BinkBufferClear@8','_BinkBufferClose@4',
    '_BinkBufferGetDescription@4','_BinkBufferGetError@0','_BinkBufferLock@4','_BinkBufferOpen@16',
    '_BinkBufferSetDirectDraw@8','_BinkBufferSetHWND@8','_BinkBufferSetOffset@12','_BinkBufferSetResolution@12',
    '_BinkBufferSetScale@12','_BinkBufferUnlock@4','_BinkCheckCursor@20','_BinkClose@4',
    '_BinkCloseTrack@4','_BinkCopyToBuffer@28','_BinkCopyToBufferRect@44','_BinkDDSurfaceType@4',
    '_BinkDX8SurfaceType@4','_BinkDoFrame@4','_BinkGetError@0','_BinkGetKeyFrame@12',
    '_BinkGetRealtime@12','_BinkGetRects@8','_BinkGetSummary@8','_BinkGetTrackData@8',
    '_BinkGetTrackID@8','_BinkGetTrackMaxSize@8','_BinkGetTrackType@8','_BinkGoto@12',
    '_BinkIsSoftwareCursor@8','_BinkLogoAddress@0','_BinkNextFrame@4','_BinkOpen@8',
    '_BinkOpenDirectSound@4','_BinkOpenMiles@4','_BinkOpenTrack@8','_BinkOpenWaveOut@4',
    '_BinkPause@8','_BinkRestoreCursor@4','_BinkService@4','_BinkSetError@4',
    '_BinkSetFrameRate@8','_BinkSetIO@4','_BinkSetIOSize@4','_BinkSetMixBinVolumes@20',
    '_BinkSetMixBins@16','_BinkSetPan@12','_BinkSetSimulate@4','_BinkSetSoundOnOff@8',
    '_BinkSetSoundSystem@8','_BinkSetSoundTrack@8','_BinkSetVideoOnOff@8','_BinkSetVolume@12',
    '_BinkWait@4','_RADSetMemory@8','_RADTimerRead@0',
    '_YUV_blit_16a1bpp@52','_YUV_blit_16a1bpp_mask@60','_YUV_blit_16a4bpp@52','_YUV_blit_16a4bpp_mask@60',
    '_YUV_blit_16bpp@48','_YUV_blit_16bpp_mask@56','_YUV_blit_24bpp@48','_YUV_blit_24bpp_mask@56',
    '_YUV_blit_24rbpp@48','_YUV_blit_24rbpp_mask@56','_YUV_blit_32abpp@52','_YUV_blit_32abpp_mask@60',
    '_YUV_blit_32bpp@48','_YUV_blit_32bpp_mask@56','_YUV_blit_32rabpp@52','_YUV_blit_32rabpp_mask@60',
    '_YUV_blit_32rbpp@48','_YUV_blit_32rbpp_mask@56','_YUV_blit_UYVY@48','_YUV_blit_UYVY_mask@56',
    '_YUV_blit_YUY2@48','_YUV_blit_YUY2_mask@56','_YUV_blit_YV12@52','_YUV_init@4',
    '_radfree@4','_radmalloc@4',
]

def get_exports(fn):
    d = open(fn, 'rb').read()
    e = struct.unpack_from('<I', d, 0x3C)[0]
    nsec = struct.unpack_from('<H', d, e+6)[0]
    opt = struct.unpack_from('<H', d, e+20)[0]
    s = e + 24 + opt
    def rva_to_off(rva):
        for i in range(nsec):
            o = s + i*40
            vsz,vaddr,rawsz,rawptr = struct.unpack_from('<IIII', d, o+8)
            if vaddr <= rva < vaddr+max(vsz,rawsz):
                return rawptr + (rva - vaddr)
        return None
    ed = struct.unpack_from('<I', d, e+24+96)[0]
    off = rva_to_off(ed)
    nnames = struct.unpack_from('<I', d, off+24)[0]
    names_rva = struct.unpack_from('<I', d, off+32)[0]
    noff = rva_to_off(names_rva)
    names = []
    for i in range(nnames):
        n = struct.unpack_from('<I', d, noff+i*4)[0]
        no = rva_to_off(n)
        names.append(d[no:no+64].split(b'\x00')[0].decode())
    return names

BASE = r'I:\SteamLibrary\steamapps\common'
cands = [
    r'Command & Conquer Generals - Zero Hour/BINKW32.DLL',
    r'Command & Conquer Red Alert II/BINKW32.DLL',
    r'Command and Conquer Generals/BINKW32.DLL',
    r'Fallout New Vegas/Backup/binkw32.dll',
    r'Impossible Creatures/binkw32.dll',
    r'PAL3/binkw32.dll',
]
enclave_set = set(ENCLAVE_EXPORTS)
for f in cands:
    p = os.path.join(BASE, f)
    if not os.path.isfile(p):
        print('MISSING:', f); continue
    names = get_exports(p)
    s1 = set(names)
    common = len(enclave_set & s1)
    missing = sorted(enclave_set - s1)
    extra = sorted(s1 - enclave_set)
    has_logo = '_BinkLogoAddress@0' in names
    print('%s' % f)
    print('  导出=%d 交集=%d Logo=%s' % (len(names), common, has_logo))
    print('  缺: %s' % missing[:5])
    print('  多: %s' % extra[:5])
    print()
