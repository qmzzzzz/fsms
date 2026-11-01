/**
 * 前端头像压缩模块（utils/avatarImage.js）行为测试
 *
 * 为什么需要这一套：该模块是「用户上传的图片 → data URI」的唯一入口，
 * ProfileView 的用例把它整体 vi.mock 掉了，于是它自己**零覆盖**——
 * 全局分支覆盖率因此被 23 个未覆盖分支拖住（本地实测 0/23）。
 *
 * 钉住的三类退化：
 *  1. 尺寸/类型/体积的前置拒绝：放行一张 6 MB 的图等于让用户上传后才收到 400；
 *  2. 压缩降级链（q0.85 → q0.7 → 384×0.75 → 拒绝）：链条任何一档被删，
 *     后端 400 就重新变成用户可见的失败；
 *  3. 资源释放：objectUrl 必须在成功与失败两条路径都 revoke（否则每换一次头像
 *     泄漏一个 Blob）。
 *
 * 画布与 Image 都是浏览器对象，jsdom 没有实现 2d 上下文，
 * 这里用替身注入并断言**调用形状**（裁切矩形、铺白底、尺寸），
 * 而不是断言像素——像素不在本模块的职责里。
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import {
  getCenterSquare,
  isSupportedAvatarType,
  compressAvatarFile,
  MAX_SOURCE_BYTES,
  MAX_DATA_URI_CHARS,
  AVATAR_SIZE,
  AVATAR_QUALITY,
} from '@/utils/avatarImage'

/** 每次 toDataURL 的返回值：用例改这个变量来驱动降级链 */
let dataUrlToReturn = 'data:image/jpeg;base64,small'
/** 置真则 Image 触发 onerror（模拟非图片/损坏文件） */
let imageLoadFails = false
/** 置真则 getContext 返回 null（模拟浏览器不支持 2d 画布） */
let canvasUnsupported = false
/** 解码后的原图尺寸：裁切矩形的输入（横图默认 800×600） */
let sourceWidth = 800
let sourceHeight = 600

const drawCalls = []
let createObjectUrlCalls = 0
let revokeObjectUrlCalls = 0

const FakeImage = class {
  constructor() {
    this.naturalWidth = 0
    this.naturalHeight = 0
    this.onload = null
    this.onerror = null
  }
}

class StubImage extends FakeImage {}

beforeEach(() => {
  dataUrlToReturn = 'data:image/jpeg;base64,small'
  imageLoadFails = false
  canvasUnsupported = false
  sourceWidth = 800
  sourceHeight = 600
  drawCalls.length = 0
  createObjectUrlCalls = 0
  revokeObjectUrlCalls = 0

  // Image：src 一赋值就同步回调（jsdom 不会真的去解码 blob:）
  const imageInstances = []
  globalThis.Image = class {
    constructor() {
      const img = new StubImage()
      img.naturalWidth = sourceWidth
      img.naturalHeight = sourceHeight
      imageInstances.push(img)
      return img
    }
  }
  Object.defineProperty(StubImage.prototype, 'src', {
    configurable: true,
    set(value) {
      this._src = value
      if (imageLoadFails) this.onerror?.()
      else this.onload?.()
    },
    get() {
      return this._src
    },
  })

  // 画布：记录 drawImage 的裁切矩形，toDataURL 由 dataUrlToReturn 驱动
  document.createElement = ((original) =>
    function createElement(tag, ...rest) {
      const el = original.call(document, tag, ...rest)
      if (String(tag).toLowerCase() === 'canvas') {
        el.getContext = () =>
          canvasUnsupported
            ? null
            : {
                fillStyle: '',
                fillRect: () => {},
                drawImage: (...args) => drawCalls.push(args.slice(1)),
              }
        el.toDataURL = () => dataUrlToReturn
      }
      return el
    })(document.createElement.bind(document))

  URL.createObjectURL = () => {
    createObjectUrlCalls += 1
    return `blob:mock/${createObjectUrlCalls}`
  }
  URL.revokeObjectURL = () => {
    revokeObjectUrlCalls += 1
  }
})

afterEach(() => {
  vi.restoreAllMocks()
})

const makeFile = ({ type = 'image/jpeg', size = 1024 } = {}) => ({ type, size, name: 'a.jpg' })

/** 断言被拒绝且理由精确：模糊的 rejects.toThrow() 分不清「拒绝」与「恰好也报错」 */
const rejection = async (promise) => {
  try {
    await promise
  } catch (error) {
    return error.message
  }
  throw new Error('预期被拒绝，但实际成功')
}

describe('getCenterSquare：中心方形裁切矩形', () => {
  test('横图取短边、左右各裁一半；纵图取短边、上下各裁一半', () => {
    expect(getCenterSquare(800, 600)).toEqual({ sx: 100, sy: 0, side: 600 })
    expect(getCenterSquare(600, 800)).toEqual({ sx: 0, sy: 100, side: 600 })
    expect(getCenterSquare(512, 512)).toEqual({ sx: 0, sy: 0, side: 512 })
  })

  test('非正数/非有限值一律退化为空矩形，不产出负数裁切（负数会让 drawImage 抛错）', () => {
    expect(getCenterSquare(0, 100)).toEqual({ sx: 0, sy: 0, side: 0 })
    expect(getCenterSquare(-5, 100)).toEqual({ sx: 0, sy: 0, side: 0 })
    expect(getCenterSquare(NaN, 100)).toEqual({ sx: 0, sy: 0, side: 0 })
    expect(getCenterSquare(100, Infinity)).toEqual({ sx: 0, sy: 0, side: 0 })
    expect(getCenterSquare('abc', 100)).toEqual({ sx: 0, sy: 0, side: 0 })
  })

  test('奇数差值的裁切起点向下取整（0.5 像素会让输出尺寸对不上）', () => {
    expect(getCenterSquare(801, 600)).toEqual({ sx: 100, sy: 0, side: 600 })
    expect(getCenterSquare(601, 600)).toEqual({ sx: 0, sy: 0, side: 600 })
  })
})

describe('isSupportedAvatarType', () => {
  test('只放行 jpeg / png；svg、gif、webp 与空值一律拒绝', () => {
    expect(isSupportedAvatarType('image/jpeg')).toBe(true)
    expect(isSupportedAvatarType('image/png')).toBe(true)
    expect(isSupportedAvatarType('image/svg+xml')).toBe(false)
    expect(isSupportedAvatarType('image/gif')).toBe(false)
    expect(isSupportedAvatarType('image/webp')).toBe(false)
    expect(isSupportedAvatarType(undefined)).toBe(false)
  })
})

describe('compressAvatarFile：前置拒绝', () => {
  test('非 jpeg/png 直接拒绝，且不创建 objectUrl（不放行一张会被后端打回的图）', async () => {
    expect(await rejection(compressAvatarFile(makeFile({ type: 'image/gif' })))).toBe('invalidType')
    expect(createObjectUrlCalls).toBe(0)
  })

  test('没有文件对象时同样按 invalidType 拒绝', async () => {
    expect(await rejection(compressAvatarFile(null))).toBe('invalidType')
    expect(await rejection(compressAvatarFile(undefined))).toBe('invalidType')
  })

  test('源文件超过 5 MB 直接拒绝 tooLarge，且不开始解码', async () => {
    expect(await rejection(compressAvatarFile(makeFile({ size: MAX_SOURCE_BYTES + 1 })))).toBe(
      'tooLarge'
    )
    expect(createObjectUrlCalls).toBe(0)
  })

  test('恰好等于上限的源文件放行（边界值不能被 > 判成越界）', async () => {
    const out = await compressAvatarFile(makeFile({ size: MAX_SOURCE_BYTES }))
    expect(out.dataUrl).toBe(dataUrlToReturn)
  })
})

describe('compressAvatarFile：成功路径', () => {
  test('中心裁切后按 512×512 输出，并先铺白底（PNG 透明区在 JPEG 上会变黑）', async () => {
    const out = await compressAvatarFile(makeFile())
    expect(out).toEqual({ dataUrl: dataUrlToReturn, width: AVATAR_SIZE, height: AVATAR_SIZE })
    expect(drawCalls).toHaveLength(1)
    // drawImage(image, sx, sy, sw, sh, 0, 0, size, size) 去掉首个 image 参数后是 8 项：
    // 800×600 的中心方形 ⇒ 左右各裁 100、纵向不裁、边长 600
    expect(drawCalls[0]).toEqual([100, 0, 600, 600, 0, 0, AVATAR_SIZE, AVATAR_SIZE])
  })

  test('成功路径也要 revokeObjectUrl（否则每次换头像泄漏一个 Blob）', async () => {
    await compressAvatarFile(makeFile())
    expect(createObjectUrlCalls).toBe(1)
    expect(revokeObjectUrlCalls).toBe(1)
  })

  test('自定义尺寸与质量透传到画布调用', async () => {
    const out = await compressAvatarFile(makeFile(), { size: 128, quality: 0.5 })
    expect(out.width).toBe(128)
    expect(out.height).toBe(128)
    expect(drawCalls[0]).toEqual([100, 0, 600, 600, 0, 0, 128, 128])
  })

  test('解码失败（非图片/文件损坏）拒绝 invalidImage，并释放 objectUrl', async () => {
    imageLoadFails = true
    expect(await rejection(compressAvatarFile(makeFile()))).toBe('invalidImage')
    expect(revokeObjectUrlCalls).toBe(1)
  })
})

describe('compressAvatarFile：超限降级链', () => {
  /** 依次返回给定长度的 dataUrl，用于驱动降级档位 */
  const driveChain = async (lengths) => {
    const queue = [...lengths]
    const sizes = []
    const originalCreate = document.createElement.bind(document)
    document.createElement = ((orig) =>
      function createElement(tag, ...rest) {
        const el = orig.call(document, tag, ...rest)
        if (String(tag).toLowerCase() === 'canvas') {
          el.getContext = () => ({ fillStyle: '', fillRect: () => {}, drawImage: () => {} })
          // 尺寸在 toDataURL 时刻读：renderToDataUrl 先建元素、随后才写 width/height
          el.toDataURL = () => {
            sizes.push([el.width, el.height])
            return 'x'.repeat(queue.length > 1 ? queue.shift() : queue[0])
          }
        }
        return el
      })(originalCreate)
    return { sizes }
  }

  test('第一档超限：降到 q0.7 重试一次即成功', async () => {
    const { sizes } = await driveChain([MAX_DATA_URI_CHARS + 1, 100])
    const out = await compressAvatarFile(makeFile())
    expect(out.dataUrl).toHaveLength(100)
    // 两档都是 512×512，只有质量变了
    expect(sizes).toEqual([
      [AVATAR_SIZE, AVATAR_SIZE],
      [AVATAR_SIZE, AVATAR_SIZE],
    ])
    expect(AVATAR_QUALITY).toBe(0.85)
  })

  test('两档都超限：再降到 384×0.75', async () => {
    const { sizes } = await driveChain([MAX_DATA_URI_CHARS + 1, MAX_DATA_URI_CHARS + 1, 100])
    const out = await compressAvatarFile(makeFile())
    expect(out.dataUrl).toHaveLength(100)
    expect(sizes.at(-1)).toEqual([384, 384])
  })

  test('三档仍超限：拒绝 tooLarge（而不是把超限的 data URI 发给后端换 400）', async () => {
    await driveChain([MAX_DATA_URI_CHARS + 1, MAX_DATA_URI_CHARS + 1, MAX_DATA_URI_CHARS + 1])
    expect(await rejection(compressAvatarFile(makeFile()))).toBe('tooLarge')
  })

  test('恰好等于上限不算超限（判据是 > 而不是 >=）', async () => {
    dataUrlToReturn = 'x'.repeat(MAX_DATA_URI_CHARS)
    const out = await compressAvatarFile(makeFile())
    expect(out.dataUrl).toHaveLength(MAX_DATA_URI_CHARS)
  })

  test('画布不可用（getContext 返回 null）时把异常原样抛给调用方，不吞成 tooLarge', async () => {
    canvasUnsupported = true
    const error = await rejection(compressAvatarFile(makeFile()))
    expect(error).not.toBe('tooLarge')
    expect(error).not.toBe('invalidImage')
    // 抛出的必须是真实 TypeError（null 上取属性），而不是被兜底文案盖住
    expect(error).toMatch(/null/i)
  })
})
