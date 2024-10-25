ULONG PASCAL FAR GreEntry2();
ULONG PASCAL FAR GreEntry3();
ULONG PASCAL FAR GreEntry4();
ULONG PASCAL FAR GreEntry5();
ULONG PASCAL FAR GreEntry6();
ULONG PASCAL FAR GreEntry7();
ULONG PASCAL FAR GreEntry8();
ULONG PASCAL FAR GreEntry9();
ULONG PASCAL FAR GreEntry10();
#ifdef INCL_GRE_ARCS
#define GreGetArcParameters(a,b) (BOOL) GreEntry4((HDC)(a),(PARCPARAMS)(b),0L,0x00004000L)
#define NGreGetArcParameters 0x00004000L
#define GreSetArcParameters(a,b) (BOOL) GreEntry4((HDC)(a),(PARCPARAMS)(b),0L,0x00004001L)
#define NGreSetArcParameters 0x00004001L
#define GreArc(a,b) (int) GreEntry4((HDC)(a),(PPOINTL)(b),0L,0x00004002L)
#define NGreArc 0x00004002L
#define GrePartialArc(a,b,c,d,e) (int) GreEntry7((HDC)(a),(PPOINTL)(b),(FIXED)(c),(FIXED)(d),(FIXED)(e),0L,0x00004003L)
#define NGrePartialArc 0x00004003L
#define GreFullArcInterior(a,b) (int) GreEntry4((HDC)(a),(FIXED)(b),0L,0x00004004L)
#define NGreFullArcInterior 0x00004004L
#define GreFullArcBoundary(a,b) (int) GreEntry4((HDC)(a),(FIXED)(b),0L,0x00004005L)
#define NGreFullArcBoundary 0x00004005L
#define GreFullArcBoth(a,b) (int) GreEntry4((HDC)(a),(FIXED)(b),0L,0x00004006L)
#define NGreFullArcBoth 0x00004006L
#define GreBoxInterior(a,b) (int) GreEntry4((HDC)(a),(PBOXPARAMS)(b),0L,0x00004007L)
#define NGreBoxInterior 0x00004007L
#define GreBoxBoundary(a,b) (int) GreEntry4((HDC)(a),(PBOXPARAMS)(b),0L,0x00004008L)
#define NGreBoxBoundary 0x00004008L
#define GreBoxBoth(a,b) (int) GreEntry4((HDC)(a),(PBOXPARAMS)(b),0L,0x00004009L)
#define NGreBoxBoth 0x00004009L
#define GrePolyFillet(a,b,c) (int) GreEntry5((HDC)(a),(PPOINTL)(b),(LONG)(c),0L,0x0000400AL)
#define NGrePolyFillet 0x0000400AL
#define GrePolyFilletSharp(a,b,c,d) (int) GreEntry6((HDC)(a),(PPOINTL)(b),(LONG)(c),(PFIXED)(d),0L,0x0000400BL)
#define NGrePolyFilletSharp 0x0000400BL
#define GrePolySpline(a,b,c) (int) GreEntry5((HDC)(a),(PPOINTL)(b),(LONG)(c),0L,0x0000400CL)
#define NGrePolySpline 0x0000400CL
#define GreDrawConicsInPath(a,b,c,d) (BOOL) GreEntry6((HDC)(a),(PPATH)(b),(PCURVE)(c),(LONG)(d),0L,0x0000400DL)
#define NGreDrawConicsInPath 0x0000400DL
#define GreCookWholePath(a,b) (BOOL) GreEntry4((HDC)(a),(PPATH)(b),0L,0x0000400EL)
#define NGreCookWholePath 0x0000400EL
#define GreCookPathCurves(a,b,c) (BOOL) GreEntry5((HDC)(a),(PPATH)(b),(PPIPELINEINFO)(c),0L,0x0000400FL)
#define NGreCookPathCurves 0x0000400FL
#define GreRenderPath(a,b,c,d,e,f,g,h) (BOOL) GreEntry10((HDC)(a),(PPATH)(b),(PCURVE)(c),(LONG)(d),(LONG)(e),(LONG)(f),(PSHORTLINE)(g),(LONG)(h),0L,0x00004011L)
#define NGreRenderPath 0x00004011L
#endif
#ifdef INCL_GRE_LINES
#define GreDisjointLines(a,b,c) (int) GreEntry5((HDC)(a),(PPOINTL)(b),(LONG)(c),0L,0x00004016L)
#define NGreDisjointLines 0x00004016L
#define GreGetCurrentPosition(a,b) (BOOL) GreEntry4((HDC)(a),(PPOINTL)(b),0L,0x00004017L)
#define NGreGetCurrentPosition 0x00004017L
#define GreSetCurrentPosition(a,b) (BOOL) GreEntry4((HDC)(a),(PPOINTL)(b),0L,0x00004018L)
#define NGreSetCurrentPosition 0x00004018L
#define GrePolyLine(a,b,c) (int) GreEntry5((HDC)(a),(PPOINTL)(b),(LONG)(c),0L,0x00004019L)
#define NGrePolyLine 0x00004019L
#define GreDrawLinesInPath(a,b,c,d) (BOOL) GreEntry6((HDC)(a),(PPATH)(b),(PCURVE)(c),(LONG)(d),0L,0x0000401AL)
#define NGreDrawLinesInPath 0x0000401AL
#define GrePolyShortLine(a,b) (int) GreEntry4((HDC)(a),(PSHORTLINE)(b),0L,0x0000401BL)
#define NGrePolyShortLine 0x0000401BL
#endif
#ifdef INCL_GRE_SCANS
#define GrePolyScanline(a,b) (ULONG) GreEntry4((HDC)(a),(PSCANDATA)(b),0L,0x0000401CL)
#define NGrePolyScanline 0x0000401CL
#endif
#ifdef INCL_GRE_BITMAPS
#define GreDeviceCreateBitmap(a,b,c,d,e) (HBITMAP) GreEntry7((HDC)(a),(PBITMAPINFOHEADER)(b),(ULONG)(c),(PBYTE)(d),(PBITMAPINFO)(e),0L,0x00004023L)
#define NGreDeviceCreateBitmap 0x00004023L
#define GreDeviceDeleteBitmap(a,b,c,d) (BOOL) GreEntry6((HDC)(a),(HBITMAP)(b),(PDELETERETURN)(c),(ULONG)(d),0L,0x00004024L)
#define NGreDeviceDeleteBitmap 0x00004024L
#define GreDeviceSelectBitmap(a,b) (ULONG) GreEntry4((HDC)(a),(HBITMAP)(b),0L,0x00004025L)
#define NGreDeviceSelectBitmap 0x00004025L
#define GreBitblt(a,b,c,d,e,f,g) (int) GreEntry9((HDC)(a),(HDC)(b),(LONG)(c),(PBITBLTPARAMETERS)(d),(LONG)(e),(ULONG)(f),(PBITBLTATTRS)(g),0L,0x00004026L)
#define NGreBitblt 0x00004026L
#define GreGetPel(a,b) (LONG) GreEntry4((HDC)(a),(PPOINTL)(b),0L,0x00004027L)
#define NGreGetPel 0x00004027L
#define GreSetPel(a,b) (int) GreEntry4((HDC)(a),(PPOINTL)(b),0L,0x00004028L)
#define NGreSetPel 0x00004028L
#define GreImageData(a,b,c,d) (int) GreEntry6((HDC)(a),(PBYTE)(b),(LONG)(c),(LONG)(d),0L,0x00004029L)
#define NGreImageData 0x00004029L
#define GreSaveScreenBits(a,b) (ULONG) GreEntry4((HDC)(a),(PRECTL)(b),0L,0x0000402CL)
#define NGreSaveScreenBits 0x0000402CL
#define GreRestoreScreenBits(a,b,c,d) (BOOL) GreEntry6((HDC)(a),(LHANDLE)(b),(PRECTL)(c),(ULONG)(d),0L,0x0000402DL)
#define NGreRestoreScreenBits 0x0000402DL
#define GreDrawBorder(a,b,c,d,e,f,g) (BOOL) GreEntry9((HDC)(a),(PRECTL)(b),(LONG)(c),(LONG)(d),(COLOR)(e),(COLOR)(f),(ULONG)(g),0L,0x0000402EL)
#define NGreDrawBorder 0x0000402EL
#define GreDeviceSetCursor(a,b,c) (BOOL) GreEntry5((HDC)(a),(PPOINTL)(b),(HBITMAP)(c),0L,0x0000402FL)
#define NGreDeviceSetCursor 0x0000402FL
#define GreGetBitmapBits(a,b,c,d,e,f) (LONG) GreEntry8((HDC)(a),(HBITMAP)(b),(LONG)(c),(LONG)(d),(PBYTE)(e),(PBITMAPINFO)(f),0L,0x00004030L)
#define NGreGetBitmapBits 0x00004030L
#define GreSetBitmapBits(a,b,c,d,e,f) (LONG) GreEntry8((HDC)(a),(HBITMAP)(b),(LONG)(c),(LONG)(d),(PBYTE)(e),(PBITMAPINFO)(f),0L,0x00004031L)
#define NGreSetBitmapBits 0x00004031L
#endif
#ifdef INCL_WINPOINTERS
#define GreSetColorCursor(a,b) (BOOL) GreEntry4((HDC)(a),(PPOINTERINFO)(b),0L,0x00004032L)
#define NGreSetColorCursor 0x00004032L
#endif
#ifdef INCL_GRE_STRINGS
#define GreCharString(a,b,c) (int) GreEntry5((HDC)(a),(LONG)(b),(PCH)(c),0L,0x00004035L)
#define NGreCharString 0x00004035L
#define GreCharStringPos(a,b,c,d,e,f,g,h) (int) GreEntry10((HDC)(a),(PPOINTL)(b),(PRECTL)(c),(ULONG)(d),(LONG)(e),(PCH)(f),(PLONG)(g),(PCSP_INFO)(h),0L,0x00004036L)
#define NGreCharStringPos 0x00004036L
#define GreQueryTextBox(a,b,c,d,e) (BOOL) GreEntry7((HDC)(a),(LONG)(b),(PCH)(c),(LONG)(d),(PPOINTL)(e),0L,0x00004037L)
#define NGreQueryTextBox 0x00004037L
#define GreQueryCharPositions(a,b,c,d,e,f,g) (ULONG) GreEntry9((HDC)(a),(PPOINTL)(b),(ULONG)(c),(LONG)(d),(PCH)(e),(PLONG)(f),(PPOINTL)(g),0L,0x00004038L)
#define NGreQueryCharPositions 0x00004038L
#define GreQueryWidthTable(a,b,c,d) (BOOL) GreEntry6((HDC)(a),(LONG)(b),(LONG)(c),(PLONG)(d),0L,0x00004039L)
#define NGreQueryWidthTable 0x00004039L
#endif
#ifdef INCL_GRE_MARKERS
#define GrePolyMarker(a,b,c) (int) GreEntry5((HDC)(a),(PPOINTL)(b),(LONG)(c),0L,0x0000403AL)
#define NGrePolyMarker 0x0000403AL
#endif
#ifdef INCL_GRE_STRINGS
#define GreCharRect(a,b,c) (ULONG) GreEntry5((HDC)(a),(VioPresentationSpace FAR *)(b),(LPGridRectRef)(c),0L,0x0000403BL)
#define NGreCharRect 0x0000403BL
#define GreCharStr(a,b,c) (ULONG) GreEntry5((HDC)(a),(VioPresentationSpace FAR *)(b),(LPGridStringRef)(c),0L,0x0000403CL)
#define NGreCharStr 0x0000403CL
#define GreScrollRect(a,b,c) (ULONG) GreEntry5((HDC)(a),(VioPresentationSpace FAR *)(b),(LPScrollRectRef)(c),0L,0x0000403DL)
#define NGreScrollRect 0x0000403DL
#define GreUpdateCursor(a,b) (ULONG) GreEntry4((HDC)(a),(VioPresentationSpace FAR *)(b),0L,0x0000403EL)
#define NGreUpdateCursor 0x0000403EL
#endif
#ifdef INCL_GRE_PATHS
#define GreBeginArea(a,b) (int) GreEntry4((HDC)(a),(ULONG)(b),0L,0x00004046L)
#define NGreBeginArea 0x00004046L
#define GreEndArea(a,b) (int) GreEntry4((HDC)(a),(ULONG)(b),0L,0x00004047L)
#define NGreEndArea 0x00004047L
#define GreBeginPath(a,b) (BOOL) GreEntry4((HDC)(a),(PHID)(b),0L,0x00004048L)
#define NGreBeginPath 0x00004048L
#define GreEndPath(a,b) (BOOL) GreEntry4((HDC)(a),(ULONG)(b),0L,0x00004049L)
#define NGreEndPath 0x00004049L
#define GreCloseFigure(a) (BOOL) GreEntry3((HDC)(a),0L,0x0000404AL)
#define NGreCloseFigure 0x0000404AL
#define GreFillPath(a,b,c) (BOOL) GreEntry5((HDC)(a),(PHID)(b),(ULONG)(c),0L,0x0000404BL)
#define NGreFillPath 0x0000404BL
#define GreOutlinePath(a,b,c) (BOOL) GreEntry5((HDC)(a),(PHID)(b),(ULONG)(c),0L,0x0000404CL)
#define NGreOutlinePath 0x0000404CL
#define GreModifyPath(a,b,c) (BOOL) GreEntry5((HDC)(a),(PHID)(b),(ULONG)(c),0L,0x0000404DL)
#define NGreModifyPath 0x0000404DL
#define GreStrokePath(a,b,c) (BOOL) GreEntry5((HDC)(a),(PHID)(b),(ULONG)(c),0L,0x0000404EL)
#define NGreStrokePath 0x0000404EL
#define GreSelectClipPath(a,b,c) (BOOL) GreEntry5((HDC)(a),(PHID)(b),(ULONG)(c),0L,0x0000404FL)
#define NGreSelectClipPath 0x0000404FL
#define GreSavePath(a,b) (BOOL) GreEntry4((HDC)(a),(LONG)(b),0L,0x00004050L)
#define NGreSavePath 0x00004050L
#define GreRestorePath(a,b) (BOOL) GreEntry4((HDC)(a),(LONG)(b),0L,0x00004051L)
#define NGreRestorePath 0x00004051L
#define GreClip1DPath(a,b,c) (BOOL) GreEntry5((HDC)(a),(PPATH)(b),(PPIPELINEINFO)(c),0L,0x00004052L)
#define NGreClip1DPath 0x00004052L
#define GreDrawRawPath(a,b) (BOOL) GreEntry4((HDC)(a),(PPATH)(b),0L,0x00004053L)
#define NGreDrawRawPath 0x00004053L
#define GreDrawCookedPath(a,b,c,d) (BOOL) GreEntry6((HDC)(a),(PPATH)(b),(PCURVE)(c),(LONG)(d),0L,0x00004054L)
#define NGreDrawCookedPath 0x00004054L
#define GreAreaSetAttributes(a,b,c,d,e) (BOOL) GreEntry7((HDC)(a),(ULONG)(b),(ULONG)(c),(ULONG)(d),(PBUNDLE)(e),0L,0x00004055L)
#define NGreAreaSetAttributes 0x00004055L
#endif
#ifdef INCL_GRE_REGIONS
#define GreGetRegionBox(a,b,c) (int) GreEntry5((HDC)(a),(HRGN)(b),(PRECTL)(c),0L,0x0000405DL)
#define NGreGetRegionBox 0x0000405DL
#define GreGetRegionRects(a,b,c,d,e) (BOOL) GreEntry7((HDC)(a),(HRGN)(b),(PRECTL)(c),(PRGNRECT)(d),(PRECTL)(e),0L,0x0000405EL)
#define NGreGetRegionRects 0x0000405EL
#define GreOffsetRegion(a,b,c) (BOOL) GreEntry5((HDC)(a),(HRGN)(b),(PPOINTL)(c),0L,0x0000405FL)
#define NGreOffsetRegion 0x0000405FL
#define GrePtInRegion(a,b,c) (int) GreEntry5((HDC)(a),(HRGN)(b),(PPOINTL)(c),0L,0x00004060L)
#define NGrePtInRegion 0x00004060L
#define GreRectInRegion(a,b,c) (int) GreEntry5((HDC)(a),(HRGN)(b),(PRECTL)(c),0L,0x00004061L)
#define NGreRectInRegion 0x00004061L
#define GreCreateRectRegion(a,b,c) (HRGN) GreEntry5((HDC)(a),(PRECTL)(b),(LONG)(c),0L,0x00004062L)
#define NGreCreateRectRegion 0x00004062L
#define GreDestroyRegion(a,b) (BOOL) GreEntry4((HDC)(a),(HRGN)(b),0L,0x00004063L)
#define NGreDestroyRegion 0x00004063L
#define GreSetRectRegion(a,b,c,d) (BOOL) GreEntry6((HDC)(a),(HRGN)(b),(PRECTL)(c),(LONG)(d),0L,0x00004064L)
#define NGreSetRectRegion 0x00004064L
#define GreCombineRegion(a,b,c,d,e) (int) GreEntry7((HDC)(a),(HRGN)(b),(HRGN)(c),(HRGN)(d),(ULONG)(e),0L,0x00004065L)
#define NGreCombineRegion 0x00004065L
#define GreCombineRectRegion(a,b,c,d,e) (int) GreEntry7((HDC)(a),(HRGN)(b),(PRECTL)(c),(HRGN)(d),(ULONG)(e),0L,0x00004066L)
#define NGreCombineRectRegion 0x00004066L
#define GreCombineShortLineRegion(a,b,c) (int) GreEntry5((HDC)(a),(HRGN)(b),(PSHORTLINE)(c),0L,0x00004067L)
#define NGreCombineShortLineRegion 0x00004067L
#define GreEqualRegion(a,b,c) (int) GreEntry5((HDC)(a),(HRGN)(b),(HRGN)(c),0L,0x00004068L)
#define NGreEqualRegion 0x00004068L
#define GrePaintRegion(a,b) (int) GreEntry4((HDC)(a),(HRGN)(b),0L,0x00004069L)
#define NGrePaintRegion 0x00004069L
#define GreSetRegionOwner(a,b,c) (BOOL) GreEntry5((HDC)(a),(HRGN)(b),(ULONG)(c),0L,0x0000406AL)
#define NGreSetRegionOwner 0x0000406AL
#endif
#ifdef INCL_GRE_CLIP
#define GreGetClipBox(a,b) (int) GreEntry4((HDC)(a),(PRECTL)(b),0L,0x0000406EL)
#define NGreGetClipBox 0x0000406EL
#define GreGetClipRects(a,b,c,d) (int) GreEntry6((HDC)(a),(PRECTL)(b),(PRGNRECT)(c),(PRECTL)(d),0L,0x0000406FL)
#define NGreGetClipRects 0x0000406FL
#define GreOffsetClipRegion(a,b) (int) GreEntry4((HDC)(a),(PPOINTL)(b),0L,0x00004070L)
#define NGreOffsetClipRegion 0x00004070L
#define GrePtVisible(a,b) (int) GreEntry4((HDC)(a),(PPOINTL)(b),0L,0x00004071L)
#define NGrePtVisible 0x00004071L
#define GreRectVisible(a,b) (int) GreEntry4((HDC)(a),(PRECTL)(b),0L,0x00004072L)
#define NGreRectVisible 0x00004072L
#define GreQueryClipRegion(a) (HRGN) GreEntry3((HDC)(a),0L,0x00004073L)
#define NGreQueryClipRegion 0x00004073L
#define GreSelectClipRegion(a,b,c) (int) GreEntry5((HDC)(a),(HRGN)(b),(PHRGN)(c),0L,0x00004074L)
#define NGreSelectClipRegion 0x00004074L
#define GreIntersectClipRectangle(a,b) (int) GreEntry4((HDC)(a),(PRECTL)(b),0L,0x00004075L)
#define NGreIntersectClipRectangle 0x00004075L
#define GreExcludeClipRectangle(a,b) (int) GreEntry4((HDC)(a),(PRECTL)(b),0L,0x00004076L)
#define NGreExcludeClipRectangle 0x00004076L
#define GreSetXformRect(a,b) (ULONG) GreEntry4((HDC)(a),(PRECTL)(b),0L,0x00004077L)
#define NGreSetXformRect 0x00004077L
#define GreSaveRegion(a,b) (BOOL) GreEntry4((HDC)(a),(LONG)(b),0L,0x0000407BL)
#define NGreSaveRegion 0x0000407BL
#define GreRestoreRegion(a,b) (BOOL) GreEntry4((HDC)(a),(LONG)(b),0L,0x0000407CL)
#define NGreRestoreRegion 0x0000407CL
#define GreClipPathCurves(a,b,c) (BOOL) GreEntry5((HDC)(a),(PPATH)(b),(PPIPELINEINFO)(c),0L,0x0000407DL)
#define NGreClipPathCurves 0x0000407DL
#define GreSelectPathRegion(a,b) (int) GreEntry4((HDC)(a),(HRGN)(b),0L,0x0000407EL)
#define NGreSelectPathRegion 0x0000407EL
#define GreRegionSelectBitmap(a,b) (ULONG) GreEntry4((HDC)(a),(HBITMAP)(b),0L,0x0000407FL)
#define NGreRegionSelectBitmap 0x0000407FL
#define GreCopyClipRegion(a,b,c,d) (int) GreEntry6((HDC)(a),(HRGN)(b),(PRECTL)(c),(ULONG)(d),0L,0x00004080L)
#define NGreCopyClipRegion 0x00004080L
#define GreSetupDC(a,b,c,d,e,f) (BOOL) GreEntry8((HDC)(a),(HRGN)(b),(LONG)(c),(LONG)(d),(PRECTL)(e),(ULONG)(f),0L,0x00004081L)
#define NGreSetupDC 0x00004081L
#endif
#ifdef INCL_GRE_XFORMS
#define GreGetPageUnits(a,b) (LONG) GreEntry4((HDC)(a),(PULONG)(b),0L,0x00004083L)
#define NGreGetPageUnits 0x00004083L
#define GreSetPageUnits(a,b,c,d) (BOOL) GreEntry6((HDC)(a),(ULONG)(b),(LONG)(c),(LONG)(d),0L,0x00004084L)
#define NGreSetPageUnits 0x00004084L
#define GreGetModelXform(a,b) (BOOL) GreEntry4((HDC)(a),(PXFORM)(b),0L,0x00004085L)
#define NGreGetModelXform 0x00004085L
#define GreSetModelXform(a,b,c) (BOOL) GreEntry5((HDC)(a),(PXFORM)(b),(ULONG)(c),0L,0x00004086L)
#define NGreSetModelXform 0x00004086L
#define GreGetWindowViewportXform(a,b) (BOOL) GreEntry4((HDC)(a),(PXFORM)(b),0L,0x00004087L)
#define NGreGetWindowViewportXform 0x00004087L
#define GreSetWindowViewportXform(a,b,c) (BOOL) GreEntry5((HDC)(a),(PXFORM)(b),(ULONG)(c),0L,0x00004088L)
#define NGreSetWindowViewportXform 0x00004088L
#define GreGetGlobalViewingXform(a,b) (BOOL) GreEntry4((HDC)(a),(PXFORM)(b),0L,0x00004089L)
#define NGreGetGlobalViewingXform 0x00004089L
#define GreSetGlobalViewingXform(a,b,c) (BOOL) GreEntry5((HDC)(a),(PXFORM)(b),(ULONG)(c),0L,0x0000408AL)
#define NGreSetGlobalViewingXform 0x0000408AL
#define GreSaveXformData(a,b,c) (LONG) GreEntry5((HDC)(a),(LONG)(b),(PBYTE)(c),0L,0x0000408BL)
#define NGreSaveXformData 0x0000408BL
#define GreRestoreXformData(a,b,c) (LONG) GreEntry5((HDC)(a),(LONG)(b),(PBYTE)(c),0L,0x0000408CL)
#define NGreRestoreXformData 0x0000408CL
#define GreGetPageViewport(a,b) (BOOL) GreEntry4((HDC)(a),(PRECTL)(b),0L,0x0000408DL)
#define NGreGetPageViewport 0x0000408DL
#define GreSetPageViewport(a,b,c) (BOOL) GreEntry5((HDC)(a),(PRECTL)(b),(ULONG)(c),0L,0x0000408EL)
#define NGreSetPageViewport 0x0000408EL
#define GreGetGraphicsField(a,b) (BOOL) GreEntry4((HDC)(a),(PRECTL)(b),0L,0x00004091L)
#define NGreGetGraphicsField 0x00004091L
#define GreSetGraphicsField(a,b) (BOOL) GreEntry4((HDC)(a),(PRECTL)(b),0L,0x00004092L)
#define NGreSetGraphicsField 0x00004092L
#define GreGetViewingLimits(a,b) (BOOL) GreEntry4((HDC)(a),(PRECTL)(b),0L,0x00004093L)
#define NGreGetViewingLimits 0x00004093L
#define GreSetViewingLimits(a,b) (BOOL) GreEntry4((HDC)(a),(PRECTL)(b),0L,0x00004094L)
#define NGreSetViewingLimits 0x00004094L
#define GreQueryViewportSize(a,b,c,d) (BOOL) GreEntry6((HDC)(a),(ULONG)(b),(LONG)(c),(PVIEWPORTSIZE)(d),0L,0x00004095L)
#define NGreQueryViewportSize 0x00004095L
#define GreConvert(a,b,c,d,e) (BOOL) GreEntry7((HDC)(a),(LONG)(b),(LONG)(c),(PPOINTL)(d),(LONG)(e),0L,0x00004096L)
#define NGreConvert 0x00004096L
#define GreConvertPath(a,b,c,d,e,f) (BOOL) GreEntry8((HDC)(a),(PPATH)(b),(LONG)(c),(LONG)(d),(PCURVE)(e),(LONG)(f),0L,0x00004097L)
#define NGreConvertPath 0x00004097L
#define GreSaveXform(a,b) (BOOL) GreEntry4((HDC)(a),(LONG)(b),0L,0x00004098L)
#define NGreSaveXform 0x00004098L
#define GreRestoreXform(a,b) (BOOL) GreEntry4((HDC)(a),(LONG)(b),0L,0x00004099L)
#define NGreRestoreXform 0x00004099L
#define GreMultiplyXforms(a,b,c,d) (BOOL) GreEntry6((HDC)(a),(PXFORM)(b),(PXFORM)(c),(ULONG)(d),0L,0x0000409AL)
#define NGreMultiplyXforms 0x0000409AL
#define GreConvertWithMatrix(a,b,c,d) (BOOL) GreEntry6((HDC)(a),(PPOINTL)(b),(LONG)(c),(PXFORM)(d),0L,0x0000409BL)
#define NGreConvertWithMatrix 0x0000409BL
#endif
#ifdef INCL_GRE_DEVMISC1
#define GreDeviceGetAttributes(a,b,c,d) (BOOL) GreEntry6((HDC)(a),(ULONG)(b),(ULONG)(c),(PBUNDLE)(d),0L,0x0000409DL)
#define NGreDeviceGetAttributes 0x0000409DL
#define GreDeviceSetAVIOFont2(a,b,c,d) (ULONG) GreEntry6((HDC)(a),(PFATTRS)(b),(PFOCAFONT)(c),(LCID)(d),0L,0x0000409EL)
#define NGreDeviceSetAVIOFont2 0x0000409EL
#define GreGetPairKerningTable(a,b,c) (ULONG) GreEntry5((HDC)(a),(LONG)(b),(PKERNINGPAIRS)(c),0L,0x000040A0L)
#define NGreGetPairKerningTable 0x000040A0L
#define GreDeviceSetAVIOFont(a,b,c) (ULONG) GreEntry5((HDC)(a),(PFOCAFONT)(b),(LCID)(c),0L,0x000040A1L)
#define NGreDeviceSetAVIOFont 0x000040A1L
#define GreDeviceSetAttributes(a,b,c,d,e) (ULONG) GreEntry7((HDC)(a),(ULONG)(b),(ULONG)(c),(ULONG)(d),(PBUNDLE)(e),0L,0x000040A2L)
#define NGreDeviceSetAttributes 0x000040A2L
#define GreDeviceSetGlobalAttribute(a,b,c,d) (ULONG) GreEntry6((HDC)(a),(ULONG)(b),(ULONG)(c),(ULONG)(d),0L,0x000040A3L)
#define NGreDeviceSetGlobalAttribute 0x000040A3L
#endif
#ifdef INCL_GRE_DEVMISC2
#define GreNotifyClipChange(a,b,c,d) (ULONG) GreEntry6((HDC)(a),(PRECTL)(b),(LONG)(c),(ULONG)(d),0L,0x000040A4L)
#define NGreNotifyClipChange 0x000040A4L
#define GreNotifyTransformChange(a,b,c) (BOOL) GreEntry5((HDC)(a),(ULONG)(b),(PNOTIFYTRANSFORMDATA)(c),0L,0x000040A5L)
#define NGreNotifyTransformChange 0x000040A5L
#define GreRealizeFont(a,b,c,d) (ULONG) GreEntry6((HDC)(a),(ULONG)(b),(PFATTRS)(c),(PFOCAFONT)(d),0L,0x000040A6L)
#define NGreRealizeFont 0x000040A6L
#define GreErasePS(a) (BOOL) GreEntry3((HDC)(a),0L,0x000040A7L)
#define NGreErasePS 0x000040A7L
#define GreSetStyleRatio(a,b) (BOOL) GreEntry4((HDC)(a),(PBYTE)(b),0L,0x000040A8L)
#define NGreSetStyleRatio 0x000040A8L
#define GreDeviceQueryFontAttributes(a,b,c) (BOOL) GreEntry5((HDC)(a),(LONG)(b),(PFONTMETRICS)(c),0L,0x000040A9L)
#define NGreDeviceQueryFontAttributes 0x000040A9L
#define GreDeviceQueryFonts(a,b,c,d,e,f) (LONG) GreEntry8((HDC)(a),(ULONG)(b),(PSZ)(c),(PFONTMETRICS)(d),(LONG)(e),(PLONG)(f),0L,0x000040AAL)
#define NGreDeviceQueryFonts 0x000040AAL
#define GreDeviceInvalidateVisRegion(a,b,c) (BOOL) GreEntry5((HDC)(a),(LONG)(b),(PDC_BLOCK)(c),0L,0x000040ABL)
#define NGreDeviceInvalidateVisRegion 0x000040ABL
#endif
#ifdef INCL_GRE_PICK
#define GreGetPickWindow(a,b) (BOOL) GreEntry4((HDC)(a),(PRECTL)(b),0L,0x000040ACL)
#define NGreGetPickWindow 0x000040ACL
#define GreSetPickWindow(a,b) (BOOL) GreEntry4((HDC)(a),(PRECTL)(b),0L,0x000040ADL)
#define NGreSetPickWindow 0x000040ADL
#endif
#ifdef INCL_GRE_DEVMISC3
#define GreResetBounds(a,b) (BOOL) GreEntry4((HDC)(a),(ULONG)(b),0L,0x000040AEL)
#define NGreResetBounds 0x000040AEL
#define GreGetBoundsData(a,b,c) (BOOL) GreEntry5((HDC)(a),(ULONG)(b),(PRECTL)(c),0L,0x000040AFL)
#define NGreGetBoundsData 0x000040AFL
#define GreAccumulateBounds(a,b) (ULONG) GreEntry4((HDC)(a),(PRECTL)(b),0L,0x000040B0L)
#define NGreAccumulateBounds 0x000040B0L
#define GreGetCodePage(a) (LONG) GreEntry3((HDC)(a),0L,0x000040B3L)
#define NGreGetCodePage 0x000040B3L
#define GreSetCodePage(a,b) (BOOL) GreEntry4((HDC)(a),(ULONG)(b),0L,0x000040B4L)
#define NGreSetCodePage 0x000040B4L
#define GreLockDevice(a) (BOOL) GreEntry3((HDC)(a),0L,0x000040B5L)
#define NGreLockDevice 0x000040B5L
#define GreUnlockDevice(a) (BOOL) GreEntry3((HDC)(a),0L,0x000040B6L)
#define NGreUnlockDevice 0x000040B6L
#define GreDeath(a) (BOOL) GreEntry3((HDC)(a),0L,0x000040B7L)
#define NGreDeath 0x000040B7L
#define GreResurrection(a,b,c) (BOOL) GreEntry5((HDC)(a),(LONG)(b),(PBYTE)(c),0L,0x000040B8L)
#define NGreResurrection 0x000040B8L
#define GreGetDCOrigin(a,b) (BOOL) GreEntry4((HDC)(a),(PPOINTL)(b),0L,0x000040BAL)
#define NGreGetDCOrigin 0x000040BAL
#define GreDeviceSetDCOrigin(a,b) (BOOL) GreEntry4((HDC)(a),(PPOINTL)(b),0L,0x000040BBL)
#define NGreDeviceSetDCOrigin 0x000040BBL
#define GreGetLineOrigin(a,b) (LONG) GreEntry4((HDC)(a),(PPOINTL)(b),0L,0x000040BCL)
#define NGreGetLineOrigin 0x000040BCL
#define GreSetLineOrigin(a,b,c) (BOOL) GreEntry5((HDC)(a),(PPOINTL)(b),(LONG)(c),0L,0x000040BDL)
#define NGreSetLineOrigin 0x000040BDL
#endif
#ifdef INCL_GRE_DEVMISC2
#define GreGetStyleRatio(a,b) (BOOL) GreEntry4((HDC)(a),(PBYTE)(b),0L,0x000040BEL)
#define NGreGetStyleRatio 0x000040BEL
#endif
#ifdef INCL_GRE_COLORTABLE
#define GreQueryColorData(a,b,c) (BOOL) GreEntry5((HDC)(a),(LONG)(b),(PLONG)(c),0L,0x000040C3L)
#define NGreQueryColorData 0x000040C3L
#define GreQueryLogColorTable(a,b,c,d,e) (LONG) GreEntry7((HDC)(a),(ULONG)(b),(LONG)(c),(LONG)(d),(PLONG)(e),0L,0x000040C4L)
#define NGreQueryLogColorTable 0x000040C4L
#define GreCreateLogColorTable(a,b,c,d,e,f) (BOOL) GreEntry8((HDC)(a),(ULONG)(b),(ULONG)(c),(LONG)(d),(LONG)(e),(PLONG)(f),0L,0x000040C5L)
#define NGreCreateLogColorTable 0x000040C5L
#define GreRealizeColorTable(a) (BOOL) GreEntry3((HDC)(a),0L,0x000040C6L)
#define NGreRealizeColorTable 0x000040C6L
#define GreUnrealizeColorTable(a) (BOOL) GreEntry3((HDC)(a),0L,0x000040C7L)
#define NGreUnrealizeColorTable 0x000040C7L
#define GreQueryRealColors(a,b,c,d,e) (LONG) GreEntry7((HDC)(a),(ULONG)(b),(LONG)(c),(LONG)(d),(PLONG)(e),0L,0x000040C8L)
#define NGreQueryRealColors 0x000040C8L
#define GreQueryNearestColor(a,b,c) (LONG) GreEntry5((HDC)(a),(ULONG)(b),(COLOR)(c),0L,0x000040C9L)
#define NGreQueryNearestColor 0x000040C9L
#define GreQueryColorIndex(a,b,c) (LONG) GreEntry5((HDC)(a),(ULONG)(b),(COLOR)(c),0L,0x000040CAL)
#define NGreQueryColorIndex 0x000040CAL
#define GreQueryRGBColor(a,b,c) (LONG) GreEntry5((HDC)(a),(ULONG)(b),(COLOR)(c),0L,0x000040CBL)
#define NGreQueryRGBColor 0x000040CBL
#endif
#ifdef INCL_GRE_DEVICE
#define GreQueryDeviceBitmaps(a,b,c) (BOOL) GreEntry5((HDC)(a),(PBITMAPFORMAT)(b),(LONG)(c),0L,0x000040D0L)
#define NGreQueryDeviceBitmaps 0x000040D0L
#define GreQueryDeviceCaps(a,b,c,d) (BOOL) GreEntry6((HDC)(a),(LONG)(b),(PLONG)(c),(LONG)(d),0L,0x000040D1L)
#define NGreQueryDeviceCaps 0x000040D1L
#define GreEscape(a,b,c,d,e,f) (LONG) GreEntry8((HDC)(a),(ULONG)(b),(LONG)(c),(PBYTE)(d),(PLONG)(e),(PBYTE)(f),0L,0x000040D2L)
#define NGreEscape 0x000040D2L
#define GreQueryHardcopyCaps(a,b,c,d) (LONG) GreEntry6((HDC)(a),(LONG)(b),(LONG)(c),(PHCINFO)(d),0L,0x000040D3L)
#define NGreQueryHardcopyCaps 0x000040D3L
#define GreQueryDevResource(a,b,c) (short) GreEntry5((HDC)(a),(ULONG)(b),(ULONG)(c),0L,0x000040D4L)
#define NGreQueryDevResource 0x000040D4L
#endif
#ifdef INCL_GRE_DCS
#define GreOpenDC(a,b,c,d,e) (HDC) GreEntry7((HDC)(a),(ULONG)(b),(PSZ)(c),(LONG)(d),(PDEVOPENDATA)(e),0L,0x00000200L)
#define NGreOpenDC 0x00000200L
#define GreCloseDC(a) (BOOL) GreEntry3((HDC)(a),0L,0x00004201L)
#define NGreCloseDC 0x00004201L
#define GreResetDC(a,b) (ULONG) GreEntry4((HDC)(a),(ULONG)(b),0L,0x00004202L)
#define NGreResetDC 0x00004202L
#define GreGetHandle(a,b) (LONG) GreEntry4((HDC)(a),(ULONG)(b),0L,0x00004203L)
#define NGreGetHandle 0x00004203L
#define GreSetHandle(a,b,c) (BOOL) GreEntry5((HDC)(a),(LHANDLE)(b),(ULONG)(c),0L,0x00004204L)
#define NGreSetHandle 0x00004204L
#define GreGetProcessControl(a) (LONG) GreEntry3((HDC)(a),0L,0x00004205L)
#define NGreGetProcessControl 0x00004205L
#define GreSetProcessControl(a,b,c) (BOOL) GreEntry5((HDC)(a),(ULONG)(b),(ULONG)(c),0L,0x00004206L)
#define NGreSetProcessControl 0x00004206L
#define GreSaveDC(a) (LONG) GreEntry3((HDC)(a),0L,0x00004207L)
#define NGreSaveDC 0x00004207L
#define GreRestoreDC(a,b) (BOOL) GreEntry4((HDC)(a),(LONG)(b),0L,0x00004208L)
#define NGreRestoreDC 0x00004208L
#define GreQueryDeviceNames(a,b,c,d,e,f) (BOOL) GreEntry8((PSZ)(a),(PLONG)(b),(PSTR32)(c),(PSTR64)(d),(PLONG)(e),(PSTR16)(f),0L,0x00000209L)
#define NGreQueryDeviceNames 0x00000209L
#define GreQueryEngineVersion() (LONG) GreEntry2(0L,0x0000020AL)
#define NGreQueryEngineVersion 0x0000020AL
#define GreSetDCOwner(a,b) (BOOL) GreEntry4((HDC)(a),(ULONG)(b),0L,0x0000420BL)
#define NGreSetDCOwner 0x0000420BL
#endif
#ifdef INCL_GRE_DEVSUPPORT
#define GreInvalidateVisRegion(a,b,c) (BOOL) GreEntry5((HDC)(a),(LONG)(b),(PDC_BLOCK)(c),0L,0x0000420FL)
#define NGreInvalidateVisRegion 0x0000420FL
#define GreCreateBitmap(a,b,c,d,e) (HBITMAP) GreEntry7((HDC)(a),(PBITMAPINFOHEADER)(b),(ULONG)(c),(PBYTE)(d),(PBITMAPINFO)(e),0L,0x00004210L)
#define NGreCreateBitmap 0x00004210L
#define GreDeleteBitmap(a) (BOOL) GreEntry3((HBITMAP)(a),0L,0x00000211L)
#define NGreDeleteBitmap 0x00000211L
#define GreSelectBitmap(a,b) (HBITMAP) GreEntry4((HDC)(a),(HBITMAP)(b),0L,0x00004212L)
#define NGreSelectBitmap 0x00004212L
#define GreGetBitmapParameters(a,b) (BOOL) GreEntry4((HBITMAP)(a),(PBITMAPINFOHEADER)(b),0L,0x00000213L)
#define NGreGetBitmapParameters 0x00000213L
#define GreGetBitmapDimension(a,b) (BOOL) GreEntry4((HBITMAP)(a),(PSIZEL)(b),0L,0x00000214L)
#define NGreGetBitmapDimension 0x00000214L
#define GreSetBitmapDimension(a,b) (BOOL) GreEntry4((HBITMAP)(a),(PSIZEL)(b),0L,0x00000215L)
#define NGreSetBitmapDimension 0x00000215L
#define GreSetCursor(a,b,c) (BOOL) GreEntry5((HDC)(a),(PPOINTL)(b),(HBITMAP)(c),0L,0x00004216L)
#define NGreSetCursor 0x00004216L
#define GreGetAttributes(a,b,c,d) (LONG) GreEntry6((HDC)(a),(ULONG)(b),(ULONG)(c),(PBUNDLE)(d),0L,0x00004217L)
#define NGreGetAttributes 0x00004217L
#define GreSetAttributes(a,b,c,d,e) (BOOL) GreEntry7((HDC)(a),(ULONG)(b),(ULONG)(c),(ULONG)(d),(PBUNDLE)(e),0L,0x00004218L)
#define NGreSetAttributes 0x00004218L
#define GreSetGlobalAttribute(a,b,c,d) (BOOL) GreEntry6((HDC)(a),(ULONG)(b),(ULONG)(c),(ULONG)(d),0L,0x00004219L)
#define NGreSetGlobalAttribute 0x00004219L
#define GreSetBitmapOwner(a,b) (BOOL) GreEntry4((HBITMAP)(a),(ULONG)(b),0L,0x0000021AL)
#define NGreSetBitmapOwner 0x0000021AL
#define GreGetDefaultAttributes(a,b,c,d) (BOOL) GreEntry6((HDC)(a),(ULONG)(b),(ULONG)(c),(PBUNDLE)(d),0L,0x0000421BL)
#define NGreGetDefaultAttributes 0x0000421BL
#define GreSetDefaultAttributes(a,b,c,d) (BOOL) GreEntry6((HDC)(a),(ULONG)(b),(ULONG)(c),(PBUNDLE)(d),0L,0x0000421CL)
#define NGreSetDefaultAttributes 0x0000421CL
#define GreGetDefaultArcParameters(a,b) (BOOL) GreEntry4((HDC)(a),(PARCPARAMS)(b),0L,0x0000421DL)
#define NGreGetDefaultArcParameters 0x0000421DL
#define GreSetDefaultArcParameters(a,b) (BOOL) GreEntry4((HDC)(a),(PARCPARAMS)(b),0L,0x0000421EL)
#define NGreSetDefaultArcParameters 0x0000421EL
#define GreGetDefaultViewingLimits(a,b) (BOOL) GreEntry4((HDC)(a),(PRECTL)(b),0L,0x0000421FL)
#define NGreGetDefaultViewingLimits 0x0000421FL
#define GreSetDefaultViewingLimits(a,b) (BOOL) GreEntry4((HDC)(a),(PRECTL)(b),0L,0x00004220L)
#define NGreSetDefaultViewingLimits 0x00004220L
#define GreInitializeAttributes(a,b) (BOOL) GreEntry4((HDC)(a),(ULONG)(b),0L,0x00004221L)
#define NGreInitializeAttributes 0x00004221L
#endif
#ifdef INCL_GRE_SETID
#define GreDeleteSetId(a,b) (BOOL) GreEntry4((HDC)(a),(LCID)(b),0L,0x00004222L)
#define NGreDeleteSetId 0x00004222L
#define GreQueryNumberSetIds(a,b) (LONG) GreEntry4((HDC)(a),(ULONG)(b),0L,0x00004223L)
#define NGreQueryNumberSetIds 0x00004223L
#define GreQuerySetIds(a,b,c,d,e,f) (BOOL) GreEntry8((HDC)(a),(LONG)(b),(PLONG)(c),(PSTR8)(d),(PLCID)(e),(ULONG)(f),0L,0x00004224L)
#define NGreQuerySetIds 0x00004224L
#endif
#ifdef INCL_GRE_LCID
#define GreQueryBitmapHandle(a,b) (HBITMAP) GreEntry4((HDC)(a),(LCID)(b),0L,0x00004225L)
#define NGreQueryBitmapHandle 0x00004225L
#define GreSetBitmapID(a,b,c) (BOOL) GreEntry5((HDC)(a),(HBITMAP)(b),(LCID)(c),0L,0x00004226L)
#define NGreSetBitmapID 0x00004226L
#define GreCopyDCLoadData(a,b,c) (BOOL) GreEntry5((HDC)(a),(ULONG)(b),(HDC)(c),0L,0x00004227L)
#define NGreCopyDCLoadData 0x00004227L
#endif
#ifdef INCL_GRE_FONTS
#define GreQueryLogicalFont(a,b,c,d,e) (BOOL) GreEntry7((HDC)(a),(LCID)(b),(PSTR8)(c),(PFATTRS)(d),(LONG)(e),0L,0x0000422CL)
#define NGreQueryLogicalFont 0x0000422CL
#define GreCreateLogicalFont(a,b,c,d) (BOOL) GreEntry6((HDC)(a),(LCID)(b),(PSTR8)(c),(PFATTRS)(d),0L,0x0000422DL)
#define NGreCreateLogicalFont 0x0000422DL
#define GreLoadFont(a) (BOOL) GreEntry3((PSZ)(a),0L,0x0000022EL)
#define NGreLoadFont 0x0000022EL
#define GreUnloadFont(a) (BOOL) GreEntry3((PSZ)(a),0L,0x0000022FL)
#define NGreUnloadFont 0x0000022FL
#define GreQueryFonts(a,b,c,d,e,f) (LONG) GreEntry8((HDC)(a),(ULONG)(b),(PSZ)(c),(PFONTMETRICS)(d),(LONG)(e),(PLONG)(f),0L,0x00004230L)
#define NGreQueryFonts 0x00004230L
#define GreQueryFontAttributes(a,b,c) (BOOL) GreEntry5((HDC)(a),(LONG)(b),(PFONTMETRICS)(c),0L,0x00004231L)
#define NGreQueryFontAttributes 0x00004231L
#define GreInstallIFI(a,b,c,d) (LONG) GreEntry6((ULONG)(a),(PSZ)(b),(PSZ)(c),(PSZ)(d),0L,0x00000232L)
#define NGreInstallIFI 0x00000232L
#define GreLoadPublicFont(a) (BOOL) GreEntry3((PSZ)(a),0L,0x00000233L)
#define NGreLoadPublicFont 0x00000233L
#define GreUnLoadPublicFont(a) (BOOL) GreEntry3((PSZ)(a),0L,0x00000234L)
#define NGreUnLoadPublicFont 0x00000234L
#define GreQueryCodePageVector(a) (ULONG) GreEntry3((ULONG)(a),0L,0x00000235L)
#define NGreQueryCodePageVector 0x00000235L
#define GreQueryFontFileDescriptions(a,b,c) (ULONG) GreEntry5((PSZ)(a),(PLONG)(b),(PFFDESCS)(c),0L,0x00000236L)
#define NGreQueryFontFileDescriptions 0x00000236L
#endif
#ifdef INCL_GRE_JOURNALING
#define GreAccumulateJournalFile(a) (ULONG) GreEntry3((ULONG)(a),0L,0x00000239L)
#define NGreAccumulateJournalFile 0x00000239L
#define GreCreateJournalFile(a,b,c) (ULONG) GreEntry5((PSZ)(a),(ULONG)(b),(LONG)(c),0L,0x0000023AL)
#define NGreCreateJournalFile 0x0000023AL
#define GreDeleteJournalFile(a) (ULONG) GreEntry3((LHANDLE)(a),0L,0x0000023BL)
#define NGreDeleteJournalFile 0x0000023BL
#define GreStartJournalFile(a,b) (ULONG) GreEntry4((HDC)(a),(LHANDLE)(b),0L,0x0000023CL)
#define NGreStartJournalFile 0x0000023CL
#define GreStopJournalFile(a,b) (ULONG) GreEntry4((HDC)(a),(LHANDLE)(b),0L,0x0000023DL)
#define NGreStopJournalFile 0x0000023DL
#define GrePlayJournalFile(a,b) (ULONG) GreEntry4((HDC)(a),(LHANDLE)(b),0L,0x0000023EL)
#define NGrePlayJournalFile 0x0000023EL
#define GreOpenJournalFile(a,b,c) (ULONG) GreEntry5((PSZ)(a),(ULONG)(b),(LONG)(c),0L,0x0000023FL)
#define NGreOpenJournalFile 0x0000023FL
#endif
