#![allow(unused)]

pub(crate) mod bf_utils;
pub(crate) mod entr64;
pub(crate) mod sdbf_core;

use lazy_static::lazy_static;

const _MAX_ELEM_COUNT: u32 = 192;

const DELIM_CHAR: char = ':';
const DELIM_STRING: &str = ":";
const MAGIC_DD: &str = "sdbf-dd";
const MAGIC_STREAM: &str = "sdbf";
const MAX_MAGIC_HEADER: u32 = 512;
const SDBF_VERSION: u32 = 2;

// System parameters
const BF_SIZE: u32 = 256;
const BINS: u32 = 1000;
const ENTR_POWER: u32 = 10;
const ENTR_SCALE: u32 = (BINS * (1 << ENTR_POWER));
const MAX_FILES: u32 = 1000000;
const MAX_THREADS: u32 = 512;
const MIN_FILE_SIZE: usize = 512;
const MIN_ELEM_COUNT: u32 = 6;
const MIN_REF_ELEM_COUNT: u32 = 64;
const POP_WIN_SIZE: u32 = 64;
const SD_SCORE_SCALE: f32 = 0.3;
const SYNC_SIZE: u32 = 16384;

const KB: usize = 1024;
const MB: usize = KB * KB;
const GB: usize = MB * KB;

lazy_static! {
    /// Precalculates the number of set bits for all 16-bit numbers
    static ref BIT_COUNT_16: [u8; 64 * KB] = {
        let mut bit_count_16 = [0u8; 64 * KB];

        for (i, byte) in bit_count_16.iter_mut().enumerate() {
            for bit in 0..16usize {
                if i & 0x1 << bit > 0 {
                    *byte += 1;
                }
            }
        }

        bit_count_16
    };

    /// Global parameters
    static ref SDBF_SYS: SdbfParameters = SdbfParameters::default();
}

/// BF digest (SDBF) description
pub struct Sdbf {
    /// Name (usually, source file)
    pub name: String,

    /// Number of BFs
    pub bf_count: u32,

    /// BF size in bytes (==m/8)
    pub bf_size: u32,

    /// Number of hash functions used (k)
    pub hash_count: u32,

    /// Bit mask used (must agree with m)
    pub mask: u32,

    /// Max number of elements per filter (n)
    pub max_elem: u32,

    /// Actual number of elements in last filter (n_last);
    /// ZERO means look at elem_counts value
    pub last_count: u32,

    /// Beginning of the BF cluster
    pub buffer: Vec<u8>,

    /// Hamming weight for each BF
    pub hamming: Vec<u16>,

    /// Individual elements counts for each BF (used in dd mode)
    pub elem_counts: Vec<u16>,

    /// Size of the base block in dd mode
    pub dd_block_size: u32,
}

impl Sdbf {
    pub fn new(name: String) -> Self {
        Self {
            name,
            bf_count: 1,
            hash_count: 5,
            bf_size: SDBF_SYS.bf_size,
            mask: BF_CLASS_MASKS[0],
            max_elem: SDBF_SYS.max_elem,
            last_count: 0,
            buffer: vec![],
            hamming: vec![],
            elem_counts: vec![],
            dd_block_size: 1,
        }
    }

    pub fn compute_hamming(&mut self) {
        self.hamming = Vec::with_capacity(self.bf_count as usize);

        let mut pos = 0usize;
        for (index, hamming) in self.hamming.iter_mut().enumerate() {
            for j in 0..BF_SIZE / 2 {
                *hamming += BIT_COUNT_16[self.buffer[pos] as usize] as u16;
                pos += 1;
            }
        }
    }
}

/// SDHASH global parameters
pub struct SdbfParameters {
    pub thread_cnt: u32,
    pub entr_win_size: u32,
    pub bf_size: u32,
    pub block_size: u32,
    pub pop_win_size: u32,
    pub threshold: u16,
    pub max_elem: u32,
    pub output_threshold: i32,
    pub warnings: bool,
    pub sample_size: u32,
}

impl Default for SdbfParameters {
    fn default() -> Self {
        Self {
            thread_cnt: 1,
            entr_win_size: 64,
            bf_size: 256,
            block_size: 4 * KB as u32,
            pop_win_size: 64,
            threshold: 16,
            max_elem: _MAX_ELEM_COUNT,
            output_threshold: 1,
            warnings: false,
            sample_size: 0, // sample size off
        }
    }
}

/// Ranks based on 6x100MB benchmark: txt, html, doc, xls, pdf, jpg
const ENTR64_RANKS: [u16; 1001] = [
    000, 000, 000, 000, 000, 000, 000, 000, 000, 000, 000, 000, 000, 000, 000, 000, 000, 000, 000,
    000, 000, 000, 000, 000, 000, 000, 000, 000, 000, 000, 000, 000, 000, 000, 000, 000, 000, 000,
    000, 000, 000, 000, 000, 000, 000, 000, 000, 000, 000, 000, 000, 000, 000, 000, 000, 000, 000,
    000, 000, 000, 000, 000, 000, 000, 000, 000, 000, 000, 000, 000, 000, 000, 000, 000, 000, 000,
    000, 000, 000, 000, 000, 000, 000, 000, 000, 000, 000, 000, 000, 000, 000, 000, 000, 000, 000,
    000, 000, 000, 000, 000, 101, 102, 106, 112, 108, 107, 103, 100, 109, 113, 128, 131, 141, 111,
    146, 153, 148, 134, 145, 110, 114, 116, 130, 124, 119, 105, 104, 118, 120, 132, 164, 180, 160,
    229, 257, 211, 189, 154, 127, 115, 129, 142, 138, 125, 136, 126, 155, 156, 172, 144, 158, 117,
    203, 214, 221, 207, 201, 123, 122, 121, 135, 140, 157, 150, 170, 387, 390, 365, 368, 341, 165,
    166, 194, 174, 184, 133, 139, 137, 149, 173, 162, 152, 159, 167, 190, 209, 238, 215, 222, 206,
    205, 181, 176, 168, 147, 143, 169, 161, 249, 258, 259, 254, 262, 217, 185, 186, 177, 183, 175,
    188, 192, 195, 182, 151, 163, 199, 239, 265, 268, 242, 204, 197, 193, 191, 218, 208, 171, 178,
    241, 200, 236, 293, 301, 256, 260, 290, 240, 216, 237, 255, 232, 233, 225, 210, 196, 179, 202,
    212, 420, 429, 425, 421, 427, 250, 224, 234, 219, 230, 220, 269, 247, 261, 235, 327, 332, 337,
    342, 340, 252, 187, 223, 198, 245, 243, 263, 228, 248, 231, 275, 264, 298, 310, 305, 309, 270,
    266, 251, 244, 213, 227, 273, 284, 281, 318, 317, 267, 291, 278, 279, 303, 452, 456, 453, 446,
    450, 253, 226, 246, 271, 277, 295, 302, 299, 274, 276, 285, 292, 289, 272, 300, 297, 286, 314,
    311, 287, 283, 288, 280, 296, 304, 308, 282, 402, 404, 401, 415, 418, 313, 320, 307, 315, 294,
    306, 326, 321, 331, 336, 334, 316, 328, 322, 324, 325, 330, 329, 312, 319, 323, 352, 345, 358,
    373, 333, 346, 338, 351, 343, 405, 389, 396, 392, 411, 378, 350, 388, 407, 423, 419, 409, 395,
    353, 355, 428, 441, 449, 474, 475, 432, 457, 448, 435, 462, 470, 467, 468, 473, 426, 494, 487,
    506, 504, 517, 465, 459, 439, 472, 522, 520, 541, 540, 527, 482, 483, 476, 480, 721, 752, 751,
    728, 730, 490, 493, 495, 512, 536, 535, 515, 528, 518, 507, 513, 514, 529, 516, 498, 492, 519,
    508, 544, 547, 550, 546, 545, 511, 532, 543, 610, 612, 619, 649, 691, 561, 574, 591, 572, 553,
    551, 565, 597, 593, 580, 581, 642, 578, 573, 626, 696, 584, 585, 595, 590, 576, 579, 583, 605,
    569, 560, 558, 570, 556, 571, 656, 657, 622, 624, 631, 555, 566, 564, 562, 557, 582, 589, 603,
    598, 604, 586, 577, 588, 613, 615, 632, 658, 625, 609, 614, 592, 600, 606, 646, 660, 666, 679,
    685, 640, 645, 675, 681, 672, 747, 723, 722, 697, 686, 601, 647, 677, 741, 753, 750, 715, 707,
    651, 638, 648, 662, 667, 670, 684, 674, 693, 678, 664, 652, 663, 639, 680, 682, 698, 695, 702,
    650, 676, 669, 665, 688, 687, 701, 700, 706, 683, 718, 703, 713, 720, 716, 735, 719, 737, 726,
    744, 736, 742, 740, 739, 731, 711, 725, 710, 704, 708, 689, 729, 727, 738, 724, 733, 692, 659,
    705, 654, 690, 655, 671, 628, 634, 621, 616, 630, 599, 629, 611, 620, 607, 623, 618, 617, 635,
    636, 641, 637, 633, 644, 653, 699, 694, 714, 734, 732, 746, 749, 755, 745, 757, 756, 758, 759,
    761, 763, 765, 767, 771, 773, 774, 775, 778, 782, 784, 786, 788, 793, 794, 797, 798, 803, 804,
    807, 809, 816, 818, 821, 823, 826, 828, 829, 834, 835, 839, 843, 846, 850, 859, 868, 880, 885,
    893, 898, 901, 904, 910, 911, 913, 916, 919, 922, 924, 930, 927, 931, 938, 940, 937, 939, 941,
    934, 936, 932, 933, 929, 928, 926, 925, 923, 921, 920, 918, 917, 915, 914, 912, 909, 908, 907,
    906, 900, 903, 902, 905, 896, 899, 897, 895, 891, 894, 892, 889, 883, 890, 888, 879, 887, 886,
    882, 878, 884, 877, 875, 872, 876, 870, 867, 874, 873, 871, 869, 881, 863, 865, 864, 860, 853,
    855, 852, 849, 857, 856, 862, 858, 861, 854, 851, 848, 847, 845, 844, 841, 840, 837, 836, 833,
    832, 831, 830, 827, 824, 825, 822, 820, 819, 817, 815, 812, 814, 810, 808, 806, 805, 799, 796,
    795, 790, 787, 785, 783, 781, 777, 776, 772, 770, 768, 769, 764, 762, 760, 754, 743, 717, 712,
    668, 661, 643, 627, 608, 594, 587, 568, 559, 552, 548, 542, 539, 537, 534, 533, 531, 525, 521,
    510, 505, 497, 496, 491, 486, 485, 478, 477, 466, 469, 463, 458, 460, 444, 440, 424, 433, 403,
    410, 394, 393, 385, 377, 379, 382, 383, 380, 384, 372, 370, 375, 366, 354, 363, 349, 357, 347,
    364, 367, 359, 369, 360, 374, 344, 376, 335, 371, 339, 361, 348, 356, 362, 381, 386, 391, 397,
    399, 398, 412, 408, 414, 422, 416, 430, 417, 434, 400, 436, 437, 438, 442, 443, 447, 406, 451,
    413, 454, 431, 455, 445, 461, 464, 471, 479, 481, 484, 489, 488, 499, 500, 509, 530, 523, 538,
    526, 549, 554, 563, 602, 596, 673, 567, 748, 575, 766, 709, 779, 780, 789, 813, 811, 838, 842,
    866, 942, 935, 944, 943, 947, 952, 951, 955, 954, 957, 960, 959, 967, 966, 969, 962, 968, 953,
    972, 961, 982, 979, 978, 981, 980, 990, 987, 988, 984, 983, 989, 985, 986, 977, 976, 975, 973,
    974, 970, 971, 965, 964, 963, 956, 958, 524, 950, 948, 949, 945, 946, 800, 801, 802, 791, 792,
    501, 502, 503, 000, 000, 000, 000, 000, 000, 000, 000, 000, 000,
];

pub(crate) const BIT_MASKS: [u32; 32] = [
    0x01, 0x03, 0x07, 0x0F, 0x1F, 0x3F, 0x7F, 0xFF, 0x01FF, 0x03FF, 0x07FF, 0x0FFF, 0x1FFF, 0x3FFF,
    0x7FFF, 0xFFFF, 0x01FFFF, 0x03FFFF, 0x07FFFF, 0x0FFFFF, 0x1FFFFF, 0x3FFFFF, 0x7FFFFF, 0xFFFFFF,
    0x01FFFFFF, 0x03FFFFFF, 0x07FFFFFF, 0x0FFFFFFF, 0x1FFFFFFF, 0x3FFFFFFF, 0x7FFFFFFF, 0xFFFFFFFF,
];

pub(crate) const BITS: [u8; 8] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80];

pub(crate) const BF_CLASS_MASKS: [u32; 6] =
    [0x7FF, 0x7FFF, 0x7FFFF, 0x7FFFFF, 0x7FFFFFF, 0xFFFFFFFF];
