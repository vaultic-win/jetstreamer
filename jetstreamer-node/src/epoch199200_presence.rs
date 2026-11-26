//! Reconcile approximate legacy compact membership with root-verified local indexes.
use jetstreamer_firehose::index::{
    SlotOffsetIndex, SlotOffsetIndexError, get_index_base_url, slot_to_range,
};
use sha2::{Digest, Sha256};
use std::{env, fs::OpenOptions, io::Read, os::unix::fs::OpenOptionsExt};

// Every listed legacy false positive lies strictly between CID-rooted, consecutive
// physical parent and child blocks in the qualified CAR windows.
const MANIFEST_SHA: &str = "cc4250c62eee9136933a87909891041c40bf5f2bc28fde36906e071a1b7156d0";
const COHORT_257_258_MANIFEST_SHA: &str =
    "fdbc02de4dd32bcedba61b142e4c21108f7ae56f174d225b806a03f634b64941";
const COHORT_261_262_MANIFEST_SHA: &str =
    "03cf5ee3c3a92e9e167dbf0728388fa7169c09cd1b104c3fe87608a01fcd2be4";
const COHORT_267_268_MANIFEST_SHA: &str =
    "80245e30eb7dbe2ccfdac4b17110799100f6ffd2356b455751735cd93a3f4802";
const COHORT_267_270_SHA: &str = "3e0bfe7153bb17f13dc75caac88b8e4f6ff06760520d48b7f92b5d66e6c5027d";
const COHORT_270_274_SHA: &str = "a1ddfbf5ad7f7a8932895d0c2e8b6a61e5f597fbaae3790e9a719e928df2395f";
const COHORT_274_277_SHA: &str = "bfaec617dd5fdbd2294f19f223ffcd38d2ce8650e6c157c477c391efafdca4f7";
const COHORT_277_280_SHA: &str = "511f9cac500fc75eaaa86ee0e46fabee67a26d3f20f41cf38d7cb9b728fe064a";
const COHORT_280_282_SHA: &str = "af9d5fcd9383e918efaeaf5546a63f04801e08dacfb3ade962c72c801aa636d6";
const COHORT_282_287_SHA: &str = "1b77f353edca605aafc74531503ca66c1f22afcf6442a1928a35b13266e07456";
const COHORT_287_291_SHA: &str = "2371bb638798ec91fc57c57acde95c3d25e35a6a79abe61a21ed3343a9be1602";
const COHORT_296_300_SHA: &str = "19fd0979da8023048312540ecf8a8b9bec191634a0565842cb5d5ec01eb7e3f7";
const COHORT_291_295_SHA: &str = "52b459e4ba00bcd4f4ea07f96bd05598db8b250175d9160628bc965a0e93f410";
const COHORT_295_297_SHA: &str = "71ad9a50ae3c247249aebeb55ca2f22f2705142b0e5e2d7a1a78ed12b8126a79";
const COHORT_297_301_SHA: &str = "ac1adc4256323ff3d654b89f4da4452dd1f25337606109e0d1fba362976ff75a";
const SLOTS: u64 = 432_000;
const TABLE_BYTES: usize = SLOTS as usize * 12;

struct Profile {
    epoch: u64,
    raw_sha: &'static str,
    compact_sha: &'static str,
    proven_skips: &'static [u64],
}

const EPOCH_199: Profile = Profile {
    epoch: 199,
    raw_sha: "ebabf661a7608e72169e85d3be3129a575ab8f5b1d2e67d2f10c95a8de79a1ae",
    compact_sha: "ed0005ecf731c6716d52f0f67aea2ca98d1b1a31771dc1d319fb6c873c136958",
    proven_skips: &[
        85975214, 85975920, 85981443, 85984461, 85988546, 85990752, 85994522, 86016034, 86016440,
        86028032, 86032179, 86033071, 86034674, 86044661, 86057311, 86060695, 86064504, 86080868,
        86084404, 86087238, 86090573, 86097404, 86099952, 86104351, 86109815, 86125477, 86136437,
        86137036, 86142926, 86154409, 86160443, 86162129, 86166456, 86172933, 86178710, 86184359,
        86208574, 86208665, 86219603, 86233439, 86233938, 86240738, 86250434, 86263995, 86273695,
        86276159, 86284661, 86285926, 86287064, 86287945, 86288643, 86288751, 86295448, 86303362,
        86307362, 86307481, 86314226, 86321218, 86322051, 86325077, 86329026, 86330689, 86339356,
        86343053, 86346075, 86349977, 86360891, 86361771, 86363201, 86373195, 86382484, 86396856,
    ],
};

const EPOCH_200: Profile = Profile {
    epoch: 200,
    raw_sha: "d37e594b89638dac4fb8ca094bccce5c388f5c583472a592dec1ed811c749cd7",
    compact_sha: "53b10b76265b4feff785c1f60c4dff4e70f4c932ab2b295237b5d7a1ace3484a",
    proven_skips: &[
        86400353, 86406549, 86417873, 86419017, 86424896, 86436299, 86439971, 86443638, 86468330,
        86476229, 86483862, 86487972, 86490504, 86490717, 86504382, 86505284, 86526623, 86530309,
        86539355, 86541582, 86543974, 86547683, 86552347, 86555877, 86570563, 86579825, 86586536,
        86592985, 86593737, 86602561, 86624468, 86634730, 86644911, 86646879, 86649599, 86654001,
        86670583, 86672779, 86676098, 86677360, 86680425, 86684353, 86691072, 86696527, 86702807,
        86704203, 86710204, 86718937, 86732704, 86746235, 86749070, 86756339, 86777659, 86782335,
        86786206, 86787008, 86787077, 86798396, 86805965, 86816583, 86823620, 86827774, 86829880,
    ],
};

const EPOCH_268: Profile = Profile {
    epoch: 268,
    raw_sha: "97a0e4ad0cbf5b99c81f1e5097625ef90b3e03364aee567c7679ba59ff4417af",
    compact_sha: "55c5d4895b620afb57afacdb7284df709217443b0fcd986849ca68a3d73eef8f",
    proven_skips: &[
        115785300, 115796349, 115800679, 115885020, 115890547, 115892696, 115932365, 115958926,
        115971936, 115977892, 116025892, 116028176, 116032670, 116071938, 116087494, 116094316,
        116105761, 116113001, 116125872,
    ],
};

const EPOCH_269: Profile = Profile {
    epoch: 269,
    raw_sha: "c36b80da05b7b8f1c7ceb0eb4eb493c5c6c71a7a6d39c26013ed6d57bef146b1",
    compact_sha: "760af23b1f4ce08bfbb82d320846c49a18fe53a6550b3e2b6f403d8633280447",
    proven_skips: &[
        116260388, 116261511, 116271319, 116282125, 116311334, 116348641, 116383321, 116419950,
        116423577, 116448001, 116457771, 116473569, 116493388, 116562945,
    ],
};
const EPOCH_270: Profile = Profile {
    epoch: 270,
    raw_sha: "8bf3e296ee3a944cb6fcd1c9ff70eaa6a59f5269a9009eaa1649cc19608434b9",
    compact_sha: "a40fecc69aef805155d276acf93c680f5628dd7eb089dad68bb6bd21fdc6e167",
    proven_skips: &[
        116667934, 116682966, 116715243, 116761379, 116807097, 116836992, 116846916, 116990228,
        117008024, 117010075, 117037937,
    ],
};
const EPOCH_257: Profile = Profile {
    epoch: 257,
    raw_sha: "5810e796b7565404320544ebb5cd98055eb5cfaf60af64884c96481e5f75d126",
    compact_sha: "bf32553fa1f47c316ca964437bbf2786279ce0ba0dae4c71655511863e666875",
    proven_skips: &[
        111060375, 111063607, 111069197, 111072511, 111078044, 111093876,
        111104068, 111124969, 111139480, 111168316, 111210884, 111226320,
        111246308, 111272761, 111276536, 111326683, 111336127, 111340860,
        111372207, 111376136, 111377548, 111379295, 111384354, 111403610,
        111410333, 111413030, 111425950, 111435316, 111435952,
    ],
};

const EPOCH_258: Profile = Profile {
    epoch: 258,
    raw_sha: "480d09c1e7d163c2f976940d4012c02c75ac383039b5515dc86a81368dbee240",
    compact_sha: "749892ec382d1b19317e6e5c6cbb171e32d269ba9e9c108525e4e010a17bc878",
    proven_skips: &[
        111456012, 111472744, 111505468, 111513184, 111533811, 111593843, 111611977, 111682235,
        111695458, 111713666, 111746497, 111844715,
    ],
};

const EPOCH_261: Profile = Profile {
    epoch: 261,
    raw_sha: "adf684d1a7354b85ae477234877c23c7eaa046de7e8b6c73cc2015d3dca02f68",
    compact_sha: "fd9a03717e4acab47e5122b241dff58686a230fa9894ee032c380d447c477673",
    proven_skips: &[
        112752259, 112754475, 112760466, 112770767, 112794584, 112795207,
        112830589, 112846318, 112880356, 112895677, 112947842, 112960930,
        112961016, 113075171, 113078372, 113094128,
    ],
};

const EPOCH_262: Profile = Profile {
    epoch: 262,
    raw_sha: "df134d946b6b92d6944f82b3eed9bff7f60d23d57466a22e59af5946e22332ea",
    compact_sha: "6b444cbc84ee2e411f749b576bda17fa1672f2dc1b3138ecb2d2079752573263",
    proven_skips: &[
        113186300, 113240852, 113259940, 113312724, 113432489, 113502214, 113514549,
        113532168, 113535052, 113545077, 113553812, 113567795, 113572235, 113577358,
        113583018, 113590552, 113601617, 113602276,
    ],
};

const EPOCH_267: Profile = Profile {
    epoch: 267,
    raw_sha: "b60ac1831d3f8850e426a6b47ee393e8260e67a9c7c473f1aea370fedd92c5e0",
    compact_sha: "f4e7038ddc675f1a232da98aedce805c30f73297d556ebe61e5ea5b2b9a1496a",
    proven_skips: &[
        115346704, 115347368, 115363157, 115372859, 115378566, 115385019, 115425045, 115473625,
        115475380, 115488514, 115489756, 115506558, 115535754, 115558078, 115578563, 115581456,
        115583627, 115610728, 115612956, 115613553, 115615519, 115620615, 115629720, 115640040,
        115662050, 115668148, 115721933, 115722433, 115747564, 115760672,
    ],
};

const EPOCH_271: Profile = Profile {
    epoch: 271,
    raw_sha: "4426d157519b8c2d985ec990f14d2b9c9537c9a61040646c1c3587189d670eff",
    compact_sha: "18d79a95d89542f77ca5095c2ca66601662da49dbfd9d2bd461240f8f785aeb2",
    proven_skips: &[
        117076328, 117096977, 117105768, 117121048, 117121725, 117122283, 117125893, 117150455,
        117159624, 117188844, 117191616, 117204356, 117235564, 117251099, 117256141, 117260365,
        117280264, 117292001, 117293330, 117307320, 117309749, 117316604, 117319663, 117329315,
        117330026, 117341517, 117342879, 117363244, 117366324, 117428878,
    ],
};

const EPOCH_272: Profile = Profile {
    epoch: 272,
    raw_sha: "80c214ab627eab724de597a1487aaadea2af11178f0290de7bc0ef22c0b51b48",
    compact_sha: "5cd681b9c2f1efa9c91134826e35dcdf32960fbeac01998559af19bed4c9959b",
    proven_skips: &[
        117564996, 117576770, 117596300, 117639544, 117650880, 117672388, 117710963, 117720819,
        117762256, 117763081, 117774647, 117833088, 117889903, 117908261, 117918075,
    ],
};

const EPOCH_273: Profile = Profile {
    epoch: 273,
    raw_sha: "222e533f4e85885bfb5e87c9733f81e0ee9657a4b2059f8e1394db1a161386f5",
    compact_sha: "2a86d4e959b2c829e04d05dd154aa31cb205e0e0e97ffd0d5556c1fc23727db9",
    proven_skips: &[
        117983227, 118127610, 118158232, 118198186, 118208016, 118240075, 118260349, 118366472,
        118366758,
    ],
};

const EPOCH_274: Profile = Profile {
    epoch: 274,
    raw_sha: "ba0ced24ed639dd354e4799c5c87c1cb9dadd43ac3e245ac9f2e6bdbda6221e0",
    compact_sha: "6984406cef13898010d9163638590fa79291bfcca650aa8c3a31e19ea667a9bb",
    proven_skips: &[
        118453640, 118590656, 118624580, 118639077, 118667452, 118756132, 118764536,
    ],
};

const EPOCH_275: Profile = Profile {
    epoch: 275,
    raw_sha: "118c2da6a0ca849d96f0da692fc2254d5108d9c56a4764a5f064300646007aa5",
    compact_sha: "6329f77569e67029b2d582acb6af262dbd8afdfa64767ac680ff0ab707f87b64",
    proven_skips: &[
        118815930, 118856405, 118862290, 118875308, 118928344, 119010764, 119036973, 119036982,
        119046156, 119061283, 119148534,
    ],
};

const EPOCH_276: Profile = Profile {
    epoch: 276,
    raw_sha: "9d5b4a277e395242436d9b2a30b6a9cb52177cc61dbe86c0f5cbd0a6ac338a34",
    compact_sha: "ab46d426cd3c44caa2e13b403f35b65b892ab7605b525ecbee0a330b373d34b3",
    proven_skips: &[
        119254120, 119266680, 119282920, 119425366, 119438792, 119479305, 119481866, 119626767,
        119636273,
    ],
};

const EPOCH_277: Profile = Profile {
    epoch: 277,
    raw_sha: "af06c34048fdd51d2cb3a0dcd99faa12d190a9938f66903094c639e1586db4dc",
    compact_sha: "882453bc7c34587eeda5eb47f504e08ef4ea75d721b50f32e2d9c891b4d6ecf5",
    proven_skips: &[
        119775240, 119778433, 119808764, 119811001, 119866452, 119870376, 119877629, 119921732,
        119997448, 120009904, 120044580, 120077396, 120095908,
    ],
};

const EPOCH_278: Profile = Profile {
    epoch: 278,
    raw_sha: "161ebfedae56fc8ab77433f78889002fc894f8525f6b7b623e1bacc707185942",
    compact_sha: "941eb78a1f76ee8b57aaa57d5e98afa8ace2b7fb7ab5fc34617e5116480df433",
    proven_skips: &[
        120125291, 120238946, 120243264, 120266585, 120281985, 120328662, 120379274, 120379427,
        120423548, 120494580,
    ],
};

const EPOCH_279: Profile = Profile {
    epoch: 279,
    raw_sha: "e3a23cd64b86da918cd7af9709e84e4e566b5820d98413b46b7f6b03ebc3a38f",
    compact_sha: "5b8c04e8697325b42ca8d5979539ff3e629cf13b45f123174547cd91b2059b3c",
    proven_skips: &[
        120594684, 120647612, 120667078, 120710000, 120712076, 120727539, 120739638, 120753242,
        120794648, 120941062, 120956779,
    ],
};

const EPOCH_280: Profile = Profile {
    epoch: 280,
    raw_sha: "7658c645e42d88d7dd11b50866c67d5924583e0a0a142452f5eec074ed6f1508",
    compact_sha: "7d33b443ee32fd7f5070f93f6bd63512a0c735c3b1633e3c128f4e836e2b8b45",
    proven_skips: &[
        120961520, 120988736, 120994430, 121030824, 121038312, 121073965, 121098768, 121115472,
        121180452, 121222636, 121238936, 121249610, 121262965, 121284819, 121323192,
    ],
};

const EPOCH_281: Profile = Profile { epoch: 281, raw_sha: "b2d2cd0b637a2df61ead3e5980cca9895daa3bb9b532d092a0b15a4fdc702c5d", compact_sha: "0a53046b08ee5580fb5ff03774a6ada6aec28a91f5bc318af38a0ddfab7f1c62", proven_skips: &[121418653, 121420619, 121424869, 121434561, 121441545, 121496210, 121546472, 121584905, 121620506, 121662399, 121732696, 121763620, 121768102, 121811333], };

const EPOCH_282: Profile = Profile { epoch: 282, raw_sha: "d87dcbcf7103728e1f8161d3915de9ae6e1d6a1d7bd403d70311ac8c5ebf21e3", compact_sha: "2dfa0271cf06e615f4bef2dd1c2fcb7b191b9ed0486ce6d0634e710a5ff5b516", proven_skips: &[121843169, 121858181, 121870077, 121909810, 121912791, 121938048, 121949965, 121991975, 122007492, 122012387, 122015613, 122027257, 122072160, 122106502, 122117031, 122123045, 122134976, 122141639, 122200029, 122209030, 122237131], };

const EPOCH_283: Profile = Profile { epoch: 283, raw_sha: "c14b2002a826d1b3ee72be64ee7b30ec0f1a6e09d19d3d3cf16808c7f4bc5f7e", compact_sha: "6e1504861613e4277e0bb9b764fe8ea9d36810e623c8b269e3c5c507176c6bf6", proven_skips: &[122257913, 122333441, 122360282, 122376748, 122400396, 122466234, 122466478, 122492290, 122506216, 122562548, 122582950, 122591879, 122607097, 122666118, 122673220], };

const EPOCH_284: Profile = Profile { epoch: 284, raw_sha: "0ce4ac8f6cf7587e3f71aa696321be3805138db6d9b653478d088695c3f6a3e6", compact_sha: "7a3734b576a8a27ff3b2454ac598a127c051ef78dff5b41454e59310706aaf75", proven_skips: &[122727689, 122747655, 122763497, 122768900, 122772107, 122802701, 122838640, 122869318, 122886530, 122919484, 122940513, 122942677, 122992594, 123000582, 123017676, 123022083, 123067087, 123074208, 123074553, 123080858, 123097649, 123103564, 123108512], };

const EPOCH_285: Profile = Profile { epoch: 285, raw_sha: "b595d27dee5411a178fec107e6fcbf97a9cf481800b0c7c3a0fa2e641b5bb2b3", compact_sha: "9adde8c6c53a7eaaa64c7579a3aa04ab962c98f296c4d4163d7baafa7a3ea31a", proven_skips: &[123129348, 123146948, 123162124, 123162683, 123189179, 123191630, 123191905, 123192908, 123309180, 123319612, 123327776, 123363904, 123365488, 123366847, 123374373, 123400588, 123404668, 123461094, 123488716, 123511649, 123526312], };

const EPOCH_286: Profile = Profile { epoch: 286, raw_sha: "8264bd00f0959c298773b83fec91328d09807159b4b7a051322641cdbdbb29d6", compact_sha: "37fd86a57f0059d35ee6c442ef61d148dbf30291ce8c6873b11fdffdbadb85e2", proven_skips: &[123569300, 123576732, 123619926, 123652232, 123762288, 123905369, 123924616, 123925539, 123952797], };

const EPOCH_287: Profile = Profile { epoch: 287, raw_sha: "84840b5814d69c57e514997a2ed696940088ce280b727b40fd269ae5922b3342", compact_sha: "a305c8579265db1240d558fbb55f8715c8e387ceacce1b628bf482333c8ef4d5", proven_skips: &[123987056, 124013282, 124044238, 124113164, 124197084, 124218451, 124256576, 124263480, 124264364, 124303310, 124323292, 124342757, 124347190, 124361448, 124373120, 124384036, 124404404], };

const EPOCH_288: Profile = Profile { epoch: 288, raw_sha: "9d3e8484fd30a47081f957bb0a0c51a295699a39a5bf8cbe2d3f655160daa0a9", compact_sha: "33b45ab949b64384e79ac901b1efccbba3f9d461356dfb282217deff0fb1e064", proven_skips: &[124421322, 124443384, 124468130, 124469896, 124470226, 124496342, 124501153, 124503340, 124532364, 124537689, 124550252, 124585180, 124586520, 124620423, 124627829, 124639920, 124696371, 124698026, 124701379, 124730372, 124764481, 124765026], };

const EPOCH_289: Profile = Profile { epoch: 289, raw_sha: "07dc4f9eb5316d4b41e72771751b5fa28347b5f9fcb30fe14c54e0c95b7f1e40", compact_sha: "11e51436e48565a8ccaedc7f29c986db0250605fb76be4428b206dfe26f7b5ad", proven_skips: &[124885876, 124933073, 124964816, 125039944, 125052852, 125066744, 125095799, 125105244, 125255635, 125274555, 125275286], };

const EPOCH_290: Profile = Profile { epoch: 290, raw_sha: "26e5a644ef5a4325a1ac85aeb24a114bff7d3373230b92ae748198d82fbfa9cd", compact_sha: "9ef2163f5bf87022660af9c3a944a6f747c4d7711a4ab6182be2c2709717f805", proven_skips: &[125317639, 125341538, 125439204, 125530076, 125556713, 125602510, 125665561], };

const EPOCH_291: Profile = Profile { epoch: 291, raw_sha: "9568ff835536291f8e794b473d463696001fd98a851d007b4552b3c765d43d2d", compact_sha: "b861fde53874950253a107aad277f9d8372d03d5249b77e4625f1e1e7c585878", proven_skips: &[125722612, 125844447, 125980483, 125988329, 125992032, 126005727, 126007633, 126015745, 126019673, 126036416, 126114254], };

const EPOCH_296: Profile = Profile { epoch: 296, raw_sha: "81078d3152a164cbd5eca30b7fde45570619a27886b84d43fde950f3b7fffc1e", compact_sha: "6fa341c5cfb426d3300843ba46a766aae2038da4eb1f79a79458c9d01fdd6a65", proven_skips: &[127876342, 127878195, 128079953, 128177295], };

const EPOCH_297: Profile = Profile { epoch: 297, raw_sha: "4f6f2e382e6ca39e850319cb3b0bfc738b99351c60ee613841d070e54640246e", compact_sha: "d1da74377c47799b96fb63336793ca6154f25a9ca8dadc4e1efe798400bfe7dc", proven_skips: &[128329488, 128372387, 128422755, 128512777, 128513761, 128531247, 128627271], };

const EPOCH_298: Profile = Profile { epoch: 298, raw_sha: "671f4f13b2c0a538260485f08d9098c5d93f07406a38945bdfea569df5e7a65a", compact_sha: "2fe786a8eb877418ba181522f165f5e7567076f7b776ccff347700d20177489c", proven_skips: &[128763252, 128844316, 128853451, 128855036, 129074200, 129126008, 129126203, 129126369, 129135514], };

const EPOCH_299: Profile = Profile { epoch: 299, raw_sha: "3c4f1bf7a3615d03274d1027799d15f9484b6e2faee82f9251928248200ffe19", compact_sha: "0c0b07d9787cc56442556eeeb5f82bf93a8016e05ea487af0d986a7681b50038", proven_skips: &[129256630, 129285283, 129287095, 129333237, 129345955, 129386947, 129393271, 129437983, 129445899, 129457721, 129470861, 129471109, 129494282, 129543075, 129550975, 129552015, 129561648, 129581275], };

const EPOCH_300: Profile = Profile { epoch: 300, raw_sha: "587d6c768ac866229eaf63fc31787281c1c87dd4c33be93992f23506998fc3ae", compact_sha: "814f4c87570a7cbaffd6b12926d624e04aaf1f0ec775cc51162dad73334bb38b", proven_skips: &[129605936, 129617749, 129618709, 129622971, 129695630, 129716208, 129721410, 129739448, 129741945, 129759472, 129775815, 129835245, 129901455, 130031072], };

const EPOCH_292: Profile = Profile { epoch: 292, raw_sha: "ac5bfe5f4a6ebcc42c9e20a5d96790ed215cacfe59e688874924f067dcd31a03", compact_sha: "7aab4a0293018aee0d9d9c2a84cfd105d0e812d1e369b284bdb0d9c673324804", proven_skips: &[126197670, 126234349, 126268166, 126274728, 126293776, 126314937, 126417552, 126504463, 126535452], };

const EPOCH_293: Profile = Profile { epoch: 293, raw_sha: "98f13211fd947a7301068fd43bbb54cadc0b197980bc4313c9195a36c3bda955", compact_sha: "cafa3bd2c286ed44f2ef304e7ad47cec6e17799a0b1de2a33d25cd5418d44334", proven_skips: &[126767672, 126830618, 126842029, 126905249, 126997940, 127006771], };

const EPOCH_294: Profile = Profile { epoch: 294, raw_sha: "32d37b50c475c0fe8b1511210e6c20adbf6b79ff7842ed53dd60553824248396", compact_sha: "c10bac0b7214036899600d2511d12ce2a864e45d235e4401984ed645e3f649d1", proven_skips: &[127065308, 127101944, 127273864, 127368881], };

const EPOCH_295: Profile = Profile { epoch: 295, raw_sha: "cfa9f4ed76b18c1dec8f3b8a7c9be326165aa2c69895b958d6c011a70ce6b0fa", compact_sha: "b4730df76fb29e793161f374afb0ec919db51bd5ef2100295e55c9a56974e5da", proven_skips: &[127454690, 127489672, 127573660, 127598777, 127600126, 127631729], };

const EPOCH_301: Profile = Profile { epoch: 301, raw_sha: "4bf09b8aa85641a685f247247750c1d2bb72ce966fe7ff7e6835feed4faca05c", compact_sha: "3a88d98cdf85f1b2d731867b6af5d4b983290b0d765122053aa89c216ac483bd", proven_skips: &[130056548, 130127166, 130160885, 130172408, 130179967, 130207133, 130236098, 130258272, 130258904, 130278719, 130297480, 130310836, 130320450, 130341526, 130368234, 130371375, 130375911, 130408153, 130443692, 130457856], };

pub(super) struct RootedSlotPresence {
    profile: &'static Profile,
    raw: Vec<u8>,
}

impl RootedSlotPresence {
    /// An ordinary replay keeps its existing sources and trust assumptions.
    pub(super) async fn configured(epoch: u64) -> Result<Option<Self>, String> {
        let (profile, manifest_sha) = match epoch {
            199 => (&EPOCH_199, MANIFEST_SHA),
            200 => (&EPOCH_200, MANIFEST_SHA),
            257 => (&EPOCH_257, "8ee8ed720d8c7e96ebc9ada87817896b8be8ed1d7703d8ff112aec7f8d4087e7"),
            258 => (&EPOCH_258, COHORT_257_258_MANIFEST_SHA),
            261 => (&EPOCH_261, "3bd36d83a86989c8db03fcdb2c5c41950182ae99b4f16202f5bc115d4357e8f9"),
            262 => (&EPOCH_262, COHORT_261_262_MANIFEST_SHA),
            267 => (
                &EPOCH_267,
                "e6f765e4fdca3f5e2c7c8bb1cda38b8ad9ff0e801dcb6df75799f74ce9e47f6f",
            ),
            268 => (
                &EPOCH_268,
                "92a805a982c8edfc24f0f4c02192c26e2ad2ab57db6a4bd9355f36eca7d26642",
            ),
            269 => (
                &EPOCH_269,
                "7428b7e662df64fdab109021fdf38fa464650744270b34ee66f4b2e630e27a1c",
            ),
            270 => (
                &EPOCH_270,
                "930dd2337cfa4abf31ca4423e9f3a3b3825c3dfae271db6ddaaccb1fbc446fb3",
            ),
            271 => (
                &EPOCH_271,
                "dfd5ea092855246ec440d5dda30c4188335b0736d8fea34bec762118621eb678",
            ),
            272 => (
                &EPOCH_272,
                "a3144eb683a7d48634b1f0838cc9ffab2d526e8d5681bf1173b386c645903fba",
            ),
            273 => (
                &EPOCH_273,
                "2227c249ea8e5cd9e87d202314e41291a87ab4d759eef26f431ebbd0e9303219",
            ),
            274 => (
                &EPOCH_274,
                "74c2a4634f067787a0fadd11a56fb6a0d40e4d848fac9eff61dc22ade0c66014",
            ),
            275 => (
                &EPOCH_275,
                "edbb168dfe490540220ba9e85d3e7044e860820a16ee793db446da248ec9b1d1",
            ),
            276 => (
                &EPOCH_276,
                "b3fa452c72aa886d263329e63c88af852e065f0bc5033b8b9cb6cf4111ea7b39",
            ),
            277 => (
                &EPOCH_277,
                "98dbe3b536d656ed3ab71d4b6021214fe83a0097aecd5dff1db134ebc58acfbc",
            ),
            278 => (
                &EPOCH_278,
                "ecd3703a8f7e76066ed3aee639f802cc5e0caf31b7d869fb1121e5cd91eb1caf",
            ),
            279 => (
                &EPOCH_279,
                "59eb0c6e560f3a126a9c60ebf7dcc9c35bbed9a3b95f8a47137c6e536571eef6",
            ),
            280 => (
                &EPOCH_280,
                "d64580f8dac288a3b269569d16c5bfa586e57072c888c4699fe16a5e17ea1061",
            ),
            281 => (&EPOCH_281, "d64568da480ef3644af1144c510ee835c0d3c40d7f1f1cd81d63dc18e61273e4"),
            282 => (&EPOCH_282, "312810c31b48ac2bf005b8d2bb6fa4f81a7f9e767c3dfc593955959590b0112f"),
            283 => (&EPOCH_283, "92755cda8f8d8fd3f96f92acde31b4cd33e733ef473319c6a05f917f737a1534"),
            284 => (&EPOCH_284, "3621a352ff1057c6fc5d5beec756af0ae5a6e5eea053df35a512444f8f75f7c4"),
            285 => (&EPOCH_285, "af2f553c3e38130ca398d95cb061642f18844716c60e44ddc4d28d319a1f5a1f"),
            286 => (&EPOCH_286, "1124c3dfba0b5bb15914d9375109a7262a9390bc1c939d64e714153cf8800d8e"),
            287 => (&EPOCH_287, "75e657ca86720f75d8888a91bc44e2b376dcd458b8c4d81eec6e79ba84b72cd0"),
            288 => (&EPOCH_288, "e2dd00891f1bc8f22ca321751e993ad32de54374ff9a942a78e76753693f7043"),
            289 => (&EPOCH_289, "c8ad407daf7103c21997d32f31b2552c4dd58d396e218c54e2057d85aa235d32"),
            290 => (&EPOCH_290, "a95a06cd0f12d4ff21e0cbb4dd20f21c9eb6658912b169d1898778dc192dcece"),
            291 => (&EPOCH_291, "97b855928409df975d51286720c8ca9f676c48dfd2fca7c798956314eadfc149"),
            296 => (&EPOCH_296, "b32dcf165a3b5a5a8030ea2929ef0f2f3ce0ebc3bec852cfad62e776dd1260bb"),
            297 => (&EPOCH_297, "f00743b996cc25a338819ccbc0ce0fc71dc0bd5f67845feef4fba12d10e7b7ad"),
            298 => (&EPOCH_298, "8852e50af51052ccd30fb79eb97df39e9635b6ecbd6eb985f1bf098444942318"),
            299 => (&EPOCH_299, "ef74e8b7777d09bd1a5b72105f76de02902172e6efd01830055de38efc67ec93"),
            300 => (&EPOCH_300, "466fde1588ec5be74a35bf88479985af9dc8d14f0b7b4105e653c8a7084c6656"),
            292 => (&EPOCH_292, "3bce93d5c4eef3c60ac2d7925f24f634e27d78eb26e7f77add0908b6166b73b5"),
            293 => (&EPOCH_293, "98ccf57d750899f084e02b71d27a694b97fae376bd54eb181636d050ef0ecb5e"),
            294 => (&EPOCH_294, "d59427ac42c7fda88a9bb5b16d9ddb031d8408c75b32f59ff906cf7df4e44dae"),
            295 => (&EPOCH_295, "6d4399db0fde7e9e8001f2e99ce26e498631ebd6bf764a39b4310f7d39efd49b"),
            301 => (&EPOCH_301, "8f95697a777fcfa128ec3c24ab1f07f182ea7287e1ea2579081d1346aea75981"),
            _ => return Ok(None),
        };
        let configured = env::var("JETSTREAMER_SLOT_RANGES_OVERRIDE_MANIFEST_SHA256").ok();
        let in_cohort = match configured.as_deref() {
            Some(COHORT_257_258_MANIFEST_SHA) => (257..=258).contains(&epoch),
            Some(COHORT_261_262_MANIFEST_SHA) => (261..=262).contains(&epoch),
            Some(COHORT_267_268_MANIFEST_SHA) => (267..=268).contains(&epoch),
            Some(COHORT_267_270_SHA) => (267..=270).contains(&epoch),
            Some(COHORT_270_274_SHA) => (270..=274).contains(&epoch),
            Some(COHORT_274_277_SHA) => (274..=277).contains(&epoch),
            Some(COHORT_277_280_SHA) => (277..=280).contains(&epoch),
            Some(COHORT_280_282_SHA) => (280..=282).contains(&epoch),
            Some(COHORT_282_287_SHA) => (282..=287).contains(&epoch),
            Some(COHORT_287_291_SHA) => (287..=291).contains(&epoch),
            Some(COHORT_296_300_SHA) => (296..=300).contains(&epoch),
            Some(COHORT_291_295_SHA) => (291..=295).contains(&epoch),
            Some(COHORT_295_297_SHA) => (295..=297).contains(&epoch),
            Some(COHORT_297_301_SHA) => (297..=301).contains(&epoch),
            _ => false,
        };
        if configured.as_deref() != Some(manifest_sha) && !in_cohort {
            return Ok(None);
        }
        if env::var_os("JETSTREAMER_SLOT_RANGES_OVERRIDE_MANIFEST").is_none() {
            return Err("missing qualified slot-ranges manifest".into());
        }
        // Resolve this through the same authenticated manifest and global index used by the
        // CAR reader. Only a missing slot from the local table identifies the acting source.
        SlotOffsetIndex::new(get_index_base_url().map_err(|err| err.to_string())?)
            .map_err(|err| err.to_string())?;
        let sentinel = profile.proven_skips[0];
        let path = match slot_to_range(sentinel).await {
            Err(SlotOffsetIndexError::SlotNotFound(slot, url))
                if slot == sentinel && url.scheme() == "file" =>
            {
                url.to_file_path()
                    .map_err(|_| "invalid local slot-ranges file URL".to_string())?
            }
            other => {
                return Err(format!(
                    "epoch {epoch} qualified slot-ranges source disagrees at {sentinel}: {other:?}"
                ));
            }
        };
        let f = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)
            .map_err(|e| e.to_string())?;
        let m = f.metadata().map_err(|e| e.to_string())?;
        if !m.is_file() || m.len() != TABLE_BYTES as u64 {
            return Err(format!(
                "epoch {epoch} invalid local slot-ranges length or type"
            ));
        }
        let mut raw = Vec::with_capacity(TABLE_BYTES);
        f.take(TABLE_BYTES as u64 + 1)
            .read_to_end(&mut raw)
            .map_err(|e| e.to_string())?;
        if raw.len() != TABLE_BYTES || format!("{:x}", Sha256::digest(&raw)) != profile.raw_sha {
            return Err(format!(
                "epoch {epoch} qualified slot-ranges content changed"
            ));
        }
        Ok(Some(Self { profile, raw }))
    }

    pub(super) fn verify_compact(&self, bytes: &[u8]) -> Result<(), String> {
        if format!("{:x}", Sha256::digest(bytes)) != self.profile.compact_sha {
            return Err(format!(
                "epoch {} independent slot-to-CID identity changed",
                self.profile.epoch
            ));
        }
        Ok(())
    }

    pub(super) fn present(&self, slot: u64, legacy: bool) -> Result<bool, String> {
        let row = slot
            .checked_sub(self.profile.epoch * SLOTS)
            .filter(|i| *i < SLOTS)
            .ok_or_else(|| format!("slot {slot} outside qualified epoch {}", self.profile.epoch))?
            as usize;
        let p = &self.raw[row * 12..(row + 1) * 12];
        let present = u32::from_le_bytes(p[8..12].try_into().unwrap()) != 0;
        let known_skip = self.profile.proven_skips.binary_search(&slot).is_ok();
        if known_skip && legacy && !present {
            return Ok(false);
        }
        if !known_skip && legacy == present {
            return Ok(present);
        }
        Err(format!(
            "unexpected legacy and rooted slot presence at slot {slot}: legacy={legacy} rooted={present} known_skip={known_skip}"
        ))
    }
}

// Uses the actual scheduler/recorder path and compact index reader. This exact
// ignored test runs under the funded offline fixture with the sealed map projected.
#[cfg(test)]
mod qualified_epoch268 {
    use super::super::{LocalSlotIndex, SlotPresenceState, build_slot_presence_map};
    use super::{Profile, RootedSlotPresence, SLOTS};
    use std::{
        env, fs,
        path::PathBuf,
        sync::{Arc, atomic::AtomicBool},
    };
    #[tokio::test]
    #[ignore = "requires sealed epoch 268 evidence and isolated CAR-header fixture"]
    async fn scheduler_uses_rooted_map() {
        check(
            &super::EPOCH_268,
            "bafyreiadrsuockl4wyx2s2nu247atdi7xhc6pc7ynhmetagg7mdkjdktgu",
        )
        .await;
    }

    #[tokio::test]
    #[ignore = "requires sealed epoch 267 evidence and isolated CAR-header fixture"]
    async fn scheduler_uses_epoch267_map() {
        check(
            &super::EPOCH_267,
            "bafyreifn4ykgns5ih2lzfzrvky2u5vfh4jvqcqy7tdylujrbvl6pqavi4m",
        )
        .await;
    }

    #[tokio::test]
    #[ignore = "requires sealed epoch 269 evidence and isolated CAR-header fixture"]
    async fn scheduler_uses_epoch269_map() {
        check(
            &super::EPOCH_269,
            "bafyreihyxzt42dpkxrmluxqvkxqfnkas7czh5igcvorg5a7fr4ckvewxzm",
        )
        .await;
    }

    #[tokio::test]
    #[ignore = "requires sealed epoch 270 evidence and isolated CAR-header fixture"]
    async fn scheduler_uses_epoch270_map() {
        check(
            &super::EPOCH_270,
            "bafyreiewpp2gte55lvp5ml7labmgudq72juwvj5o5j3jd6xyjjbaxpudcu",
        )
        .await;
    }

    #[tokio::test]
    #[ignore = "requires sealed epoch 271 evidence and isolated CAR-header fixture"]
    async fn scheduler_uses_epoch271_map() {
        check(
            &super::EPOCH_271,
            "bafyreievtg2mp5c7prfzuntr3hhljck6hbhrmkb65jmswlke6norpck4my",
        )
        .await;
    }

    #[tokio::test]
    #[ignore = "requires sealed epoch 272 evidence and isolated CAR-header fixture"]
    async fn scheduler_uses_epoch272_map() {
        check(
            &super::EPOCH_272,
            "bafyreibyphy25qwppk5bm2uum2kp3dbqrjtjljqhdulhbqxesjj5encc3a",
        )
        .await;
    }

    #[tokio::test]
    #[ignore = "requires sealed epoch 273 evidence and isolated CAR-header fixture"]
    async fn scheduler_uses_epoch273_map() {
        check(
            &super::EPOCH_273,
            "bafyreiad53lhdnph2etnrbwslfirrx7rb6r2dma2aazgm4bs5dvfw4hax4",
        )
        .await;
    }

    #[tokio::test]
    #[ignore = "requires sealed epoch 274 evidence and isolated CAR-header fixture"]
    async fn scheduler_uses_epoch274_map() {
        check(
            &super::EPOCH_274,
            "bafyreid47yanxmkgrltqmsa3lbjwnbphm6fgwj7lvvwdoait7yv2zfwglq",
        )
        .await;
    }

    #[tokio::test]
    #[ignore = "requires sealed epoch 275 evidence and isolated CAR-header fixture"]
    async fn scheduler_uses_epoch275_map() {
        check(
            &super::EPOCH_275,
            "bafyreibnfz5x3wrgf6cr737wbsnnlkyuphtl4qcdc3cnsegjvmelwnnczq",
        )
        .await;
    }

    #[tokio::test]
    #[ignore = "requires sealed epoch 276 evidence and isolated CAR-header fixture"]
    async fn scheduler_uses_epoch276_map() {
        check(
            &super::EPOCH_276,
            "bafyreidr6kpe7wvhmmu75e6epocnw7lyz7smhkf6n2r3nwmqdyzop7rfd4",
        )
        .await;
    }

    #[tokio::test]
    #[ignore = "requires sealed epoch 277 evidence and isolated CAR-header fixture"]
    async fn scheduler_uses_epoch277_map() {
        check(
            &super::EPOCH_277,
            "bafyreif67ugalao4gsy2abytaf2uu3hsz6lnvx7odbjuf65pgmirfmbk2q",
        )
        .await;
    }

    #[tokio::test]
    #[ignore = "requires sealed epoch 278 evidence and isolated CAR-header fixture"]
    async fn scheduler_uses_epoch278_map() {
        check(
            &super::EPOCH_278,
            "bafyreibwj2uert4mbjtpp5a4q4yfywk5igufgike5fbjcljygei5exty3a",
        )
        .await;
    }

    #[tokio::test]
    #[ignore = "requires sealed epoch 279 evidence and isolated CAR-header fixture"]
    async fn scheduler_uses_epoch279_map() {
        check(
            &super::EPOCH_279,
            "bafyreiewswobkyx2a67vqxgt4am47yisrrgg6kxaq5mreia5dyeikfruoi",
        )
        .await;
    }

    #[tokio::test]
    #[ignore = "requires sealed epoch 280 evidence and isolated CAR-header fixture"]
    async fn scheduler_uses_epoch280_map() {
        check(
            &super::EPOCH_280,
            "bafyreicaxdokcw7qflwsmqtbmqgias7elbm73tlqqzd53bzz7bn3phmlaq",
        )
        .await;
    }

    #[tokio::test]
    #[ignore = "requires sealed epoch 281 evidence and isolated CAR-header fixture"]
    async fn scheduler_uses_epoch281_map() {
        check(&super::EPOCH_281, "bafyreibrchqyzzvyg3sw24wluvyvkbpcn4ji3etgx2gm2rnqc2fry3gdxe").await;
    }

    #[tokio::test]
    #[ignore = "requires sealed epoch 282 evidence and isolated CAR-header fixture"]
    async fn scheduler_uses_epoch282_map() {
        check(&super::EPOCH_282, "bafyreibkincn5733dntwqsibbo6ehpxxsno5iwqtfkousxeah76inkol2u").await;
    }

    #[tokio::test]
    #[ignore = "requires sealed epoch 283 evidence and isolated CAR-header fixture"]
    async fn scheduler_uses_epoch283_map() {
        check(&super::EPOCH_283, "bafyreid66hsdd2npjbab3zfwaop3c2xfhuslz5pozra6mc66ulet64jcj4").await;
    }

    #[tokio::test]
    #[ignore = "requires sealed epoch 284 evidence and isolated CAR-header fixture"]
    async fn scheduler_uses_epoch284_map() {
        check(&super::EPOCH_284, "bafyreidt3s3do73p2hgffss7ch55joh5iabrygacb4ynjbxzpudxyf4i7a").await;
    }

    #[tokio::test]
    #[ignore = "requires sealed epoch 285 evidence and isolated CAR-header fixture"]
    async fn scheduler_uses_epoch285_map() {
        check(&super::EPOCH_285, "bafyreiam2ndwsov4oj4jelptiiat3l67kil4mj5tnovqkjv7n4bi3rjtoe").await;
    }

    #[tokio::test]
    #[ignore = "requires sealed epoch 286 evidence and isolated CAR-header fixture"]
    async fn scheduler_uses_epoch286_map() {
        check(&super::EPOCH_286, "bafyreibsdipvtbosqf75w3skclwjphlncov2is5iivnl5cccjqvm4exmbu").await;
    }

    #[tokio::test]
    #[ignore = "requires sealed epoch 287 evidence and isolated CAR-header fixture"]
    async fn scheduler_uses_epoch287_map() {
        check(&super::EPOCH_287, "bafyreiatkwxgebjpf57nclv3snf6tr3wfbk5b62xezxfjtouzxsgdwmqbq").await;
    }

    #[tokio::test]
    #[ignore = "requires sealed epoch 288 evidence and isolated CAR-header fixture"]
    async fn scheduler_uses_epoch288_map() {
        check(&super::EPOCH_288, "bafyreiahdgxtk3turqkhar76tkv4hp6kz3kaqjenlgvrwpjml5oaggmabq").await;
    }

    #[tokio::test]
    #[ignore = "requires sealed epoch 289 evidence and isolated CAR-header fixture"]
    async fn scheduler_uses_epoch289_map() {
        check(&super::EPOCH_289, "bafyreicacdmz6ivzpuaofj2ytyknmkpnkb6b5544hczun3k7acrrsdvqse").await;
    }

    #[tokio::test]
    #[ignore = "requires sealed epoch 290 evidence and isolated CAR-header fixture"]
    async fn scheduler_uses_epoch290_map() {
        check(&super::EPOCH_290, "bafyreihd6jxi75sl5polwtldkxdpatnkhhrkwh7cpjukyn42oe6pkagmiq").await;
    }

    #[tokio::test]
    #[ignore = "requires sealed epoch 291 evidence and isolated CAR-header fixture"]
    async fn scheduler_uses_epoch291_map() {
        check(&super::EPOCH_291, "bafyreiabgztwahscuxhsjqdrv7sxxs7vys4rh37krbbm5mx3ds2ftdoqyq").await;
    }

    #[tokio::test]
    #[ignore = "requires sealed epoch 296 evidence and isolated CAR-header fixture"]
    async fn scheduler_uses_epoch296_map() {
        check(&super::EPOCH_296, "bafyreig5pqhwelpi6f4fikdp4bzd6ezntyuviuxdpvlausdmv5mpzewade").await;
    }

    #[tokio::test]
    #[ignore = "requires sealed epoch 297 evidence and isolated CAR-header fixture"]
    async fn scheduler_uses_epoch297_map() {
        check(&super::EPOCH_297, "bafyreie34tp3pqsr2cxtyfxy7ugfcebu7k7yp3b7vvbavebsx7lcluc46u").await;
    }

    #[tokio::test]
    #[ignore = "requires sealed epoch 298 evidence and isolated CAR-header fixture"]
    async fn scheduler_uses_epoch298_map() {
        check(&super::EPOCH_298, "bafyreihsmeo6tbb5vbwrk7md4k4mbbmjdhkkpvqnnpcpnxmmgjxkdeyu6a").await;
    }

    #[tokio::test]
    #[ignore = "requires sealed epoch 299 evidence and isolated CAR-header fixture"]
    async fn scheduler_uses_epoch299_map() {
        check(&super::EPOCH_299, "bafyreiaom6ox5xoiql6sng2v6z53eemxqiwfaxvhkzcmysc5me4lo6xcoi").await;
    }

    #[tokio::test]
    #[ignore = "requires sealed epoch 300 evidence and isolated CAR-header fixture"]
    async fn scheduler_uses_epoch300_map() {
        check(&super::EPOCH_300, "bafyreih45lcghluasjbqciqkixfjfjufbltuu3vhhkrx6ktdkotahpklva").await;
    }

    #[tokio::test]
    #[ignore = "requires sealed epoch 292 evidence and isolated CAR-header fixture"]
    async fn scheduler_uses_epoch292_map() {
        check(&super::EPOCH_292, "bafyreie5o7qdkfcqlybizbhpyoc6yqvtbn5erdzf4g2aneatevb7p5n74a").await;
    }

    #[tokio::test]
    #[ignore = "requires sealed epoch 293 evidence and isolated CAR-header fixture"]
    async fn scheduler_uses_epoch293_map() {
        check(&super::EPOCH_293, "bafyreihykwqix4y6y5ve4dl2xgxsv4mxybemg5sivlizxkgtjdap3jj52y").await;
    }

    #[tokio::test]
    #[ignore = "requires sealed epoch 294 evidence and isolated CAR-header fixture"]
    async fn scheduler_uses_epoch294_map() {
        check(&super::EPOCH_294, "bafyreibagip3au2fkj5owmq6tswoflt266elzvcgqqls4scbiqfp2a4jre").await;
    }

    #[tokio::test]
    #[ignore = "requires sealed epoch 295 evidence and isolated CAR-header fixture"]
    async fn scheduler_uses_epoch295_map() {
        check(&super::EPOCH_295, "bafyreifit4zyjy664wgdfzc75farxhnif2xrkvlkdvi5pufh2spav7lh3m").await;
    }

    #[tokio::test]
    #[ignore = "requires sealed epoch 301 evidence and isolated CAR-header fixture"]
    async fn scheduler_uses_epoch301_map() {
        check(&super::EPOCH_301, "bafyreierz53jcmi577gn5dv5rtubzbr3szebafo6lpffv3lmura2ywmw4e").await;
    }

    async fn check(profile: &Profile, car_root: &str) {
        let epoch = profile.epoch;
        let first = epoch * SLOTS;
        let last = first + SLOTS - 1;
        let ledger =
            PathBuf::from(env::var_os(format!("HORIZON{epoch}_QUALIFIED_LEDGER")).unwrap());
        let compact = ledger.join(format!(
            "compact-indexes/{epoch}/epoch-{epoch}-{car_root}-mainnet-slot-to-cid.index"
        ));
        let bytes = fs::read(compact).unwrap();
        let raw = fs::read(format!("/var/lib/jetstreamer/horizon{epoch}-rooted-slot-ranges-v1/epoch-{epoch}-slot-ranges.raw")).unwrap();
        if env::var("JETSTREAMER_SLOT_RANGES_OVERRIDE_MANIFEST_SHA256").as_deref()
            == Ok(super::COHORT_267_270_SHA)
        {
            for sibling in 267..=270 {
                assert!(
                    RootedSlotPresence::configured(sibling)
                        .await
                        .unwrap()
                        .is_some()
                );
            }
        }
        if env::var("JETSTREAMER_SLOT_RANGES_OVERRIDE_MANIFEST_SHA256").as_deref()
            == Ok(super::COHORT_267_268_MANIFEST_SHA)
        {
            let previous = RootedSlotPresence::configured(267).await.unwrap().unwrap();
            let skip = super::EPOCH_267.proven_skips[0];
            assert!(!previous.present(skip, true).unwrap());
        }
        if env::var("JETSTREAMER_SLOT_RANGES_OVERRIDE_MANIFEST_SHA256").as_deref()
            == Ok(super::COHORT_270_274_SHA)
        {
            for sibling in 270..=274 {
                assert!(
                    RootedSlotPresence::configured(sibling)
                        .await
                        .unwrap()
                        .is_some()
                );
            }
        }
        if env::var("JETSTREAMER_SLOT_RANGES_OVERRIDE_MANIFEST_SHA256").as_deref()
            == Ok(super::COHORT_274_277_SHA)
        {
            for sibling in 274..=277 {
                assert!(
                    RootedSlotPresence::configured(sibling)
                        .await
                        .unwrap()
                        .is_some()
                );
            }
        }
        if env::var("JETSTREAMER_SLOT_RANGES_OVERRIDE_MANIFEST_SHA256").as_deref()
            == Ok(super::COHORT_277_280_SHA)
        {
            for sibling in 277..=280 {
                assert!(
                    RootedSlotPresence::configured(sibling)
                        .await
                        .unwrap()
                        .is_some()
                );
            }
        }
        if env::var("JETSTREAMER_SLOT_RANGES_OVERRIDE_MANIFEST_SHA256").as_deref() == Ok(super::COHORT_280_282_SHA) {
            for sibling in 280..=282 { assert!(RootedSlotPresence::configured(sibling).await.unwrap().is_some()); }
        }
        if env::var("JETSTREAMER_SLOT_RANGES_OVERRIDE_MANIFEST_SHA256").as_deref() == Ok(super::COHORT_282_287_SHA) {
            for sibling in 282..=287 { assert!(RootedSlotPresence::configured(sibling).await.unwrap().is_some()); }
        }
        if env::var("JETSTREAMER_SLOT_RANGES_OVERRIDE_MANIFEST_SHA256").as_deref() == Ok(super::COHORT_287_291_SHA) {
            for sibling in 287..=291 { assert!(RootedSlotPresence::configured(sibling).await.unwrap().is_some()); }
        }
        if env::var("JETSTREAMER_SLOT_RANGES_OVERRIDE_MANIFEST_SHA256").as_deref() == Ok(super::COHORT_296_300_SHA) {
            for sibling in 296..=300 { assert!(RootedSlotPresence::configured(sibling).await.unwrap().is_some()); }
        }
        if env::var("JETSTREAMER_SLOT_RANGES_OVERRIDE_MANIFEST_SHA256").as_deref() == Ok(super::COHORT_291_295_SHA) {
            for sibling in 291..=295 { assert!(RootedSlotPresence::configured(sibling).await.unwrap().is_some()); }
        }
        if env::var("JETSTREAMER_SLOT_RANGES_OVERRIDE_MANIFEST_SHA256").as_deref() == Ok(super::COHORT_295_297_SHA) {
            for sibling in 295..=297 { assert!(RootedSlotPresence::configured(sibling).await.unwrap().is_some()); }
        }
        if env::var("JETSTREAMER_SLOT_RANGES_OVERRIDE_MANIFEST_SHA256").as_deref() == Ok(super::COHORT_297_301_SHA) {
            for sibling in 297..=301 { assert!(RootedSlotPresence::configured(sibling).await.unwrap().is_some()); }
        }
        let source = RootedSlotPresence::configured(epoch)
            .await
            .unwrap()
            .unwrap();
        source.verify_compact(&bytes).unwrap();
        assert!(source.verify_compact(&bytes[..bytes.len() - 1]).is_err());
        let legacy = LocalSlotIndex::from_bytes(bytes).unwrap();
        assert_eq!(legacy.header.metadata_epoch(), Some(epoch));
        let m = build_slot_presence_map(
            first,
            last,
            Arc::new(AtomicBool::new(false)),
            &ledger,
            epoch,
        )
        .await
        .unwrap();
        let mut next = None;
        let mut false_positives = Vec::new();
        for i in (0..SLOTS as usize).rev() {
            let slot = first + i as u64;
            let offset = i * 12;
            let expected =
                u32::from_le_bytes(raw[offset + 8..offset + 12].try_into().unwrap()) != 0;
            let h = legacy.contains_slot(slot).unwrap();
            assert_eq!(source.present(slot, h).unwrap(), expected);
            assert!(source.present(slot, !h).is_err());
            assert_eq!(
                m.state(slot),
                Some(if expected {
                    SlotPresenceState::Present
                } else {
                    SlotPresenceState::Missing
                })
            );
            assert_eq!(m.next_present_after(slot), next);
            if expected {
                next = Some(slot)
            } else if h {
                false_positives.push(slot)
            }
        }
        false_positives.reverse();
        assert_eq!(false_positives.as_slice(), profile.proven_skips);
        assert!(source.present(first - 1, false).is_err());
        assert!(source.present(last + 1, false).is_err());
    }
}
#[cfg(test)]
mod qualified_epoch257 {
    use super::super::{LocalSlotIndex, SlotPresenceState, build_slot_presence_map};
    use super::{EPOCH_257, EPOCH_258, EPOCH_261, Profile, RootedSlotPresence};
    use jetstreamer_firehose::index::{SlotOffsetIndex, SlotOffsetIndexError, get_index_base_url};
    use sha2::{Digest, Sha256};
    use std::{
        env, fs,
        path::PathBuf,
        sync::{Arc, atomic::AtomicBool},
    };

    #[tokio::test]
    #[ignore = "requires original 256 warmup and sealed 257 compact and range inputs"]
    async fn singleton_warmup_and_epoch_use_qualified_membership() {
        check_singleton(
            &EPOCH_257,
            111022756,
            "bafyreienrbuyzpqtxdf2sywy67idahbpakcahmqeonwz276n62pupetgbu",
            "/var/lib/jetstreamer/horizon257-source-ranges-20261120-v1/epoch-257-slot-ranges.candidate.raw",
            "bafyreief4qucc6dk7mq62wl4jbglnii745jd6aipu52cjwbo4u6wgkwrye",
            "7fd2e109d93533c85f597f843a39ff4a34d34d69b962911452bc41f42f0d8548",
            "0138424f86f813d47e402175746e4d554dfd8d183acf2369e85b0a1f2fb4c065",
        ).await;
    }

    #[tokio::test]
    #[ignore = "requires the sealed epoch 257 and 258 range and compact indexes"]
    async fn singleton_258_warmup_and_epoch_use_qualified_membership() {
        check_singleton(
            &EPOCH_258,
            111455045,
            "bafyreicszutajk2nhrbkpfscbidbqpno6toqvwin65e77naxkzhfmltb74",
            "/var/lib/jetstreamer/horizon258-rooted-replay-inputs-v1/epoch-258-slot-ranges.candidate.raw",
            "bafyreienrbuyzpqtxdf2sywy67idahbpakcahmqeonwz276n62pupetgbu",
            EPOCH_257.raw_sha,
            EPOCH_257.compact_sha,
        ).await;
    }

    #[tokio::test]
    #[ignore = "requires original 260 warmup and sealed 261 compact and range inputs"]
    async fn singleton_261_warmup_and_epoch_use_qualified_membership() {
        check_singleton(
            &EPOCH_261,
            112751209,
            "bafyreib6vznz6e6jrjjdh3clmdfpuxauj4okmjwgldevc2svggdksch4fq",
            "/var/lib/jetstreamer/horizon261-source-ranges-v136-v1/epoch-261-slot-ranges.candidate.raw",
            "bafyreiabyb2rm444cdvvhwykyuwsaliebbnnz5o2rabpzir425gdy6cw6q",
            "38173a117b50c7a02ba5e3cf04df6a5dc38853d29463121bbf1df52214499a25",
            "aa01106930493dc616429af673bd5a98683ae3bd840e5fe28b8616e646532bdb",
        ).await;
    }

    async fn check_singleton(
        profile: &Profile,
        warmup_first: u64,
        epoch_root: &str,
        table_path: &str,
        warmup_root: &str,
        warmup_raw_sha: &str,
        warmup_compact_sha: &str,
    ) {
        let epoch = profile.epoch;
        let warmup = epoch - 1;
        let ledger =
            PathBuf::from(env::var_os(format!("HORIZON{epoch}_QUALIFIED_LEDGER")).unwrap());
        let warmup_path =
            PathBuf::from(env::var_os(format!("HORIZON{warmup}_WARMUP_RAW")).unwrap());
        let first = epoch * 432000;
        let last = first + 431999;
        let map = build_slot_presence_map(
            warmup_first,
            last,
            Arc::new(AtomicBool::new(false)),
            &ledger,
            epoch,
        )
        .await
        .unwrap();
        let client = SlotOffsetIndex::new(get_index_base_url().unwrap()).unwrap();
        let mut next = None;
        for (e, start, end, root, path, raw_sha, slot_sha) in [
            (
                epoch,
                first,
                last,
                epoch_root,
                std::path::Path::new(table_path),
                profile.raw_sha,
                profile.compact_sha,
            ),
            (
                warmup,
                warmup_first,
                first - 1,
                warmup_root,
                warmup_path.as_path(),
                warmup_raw_sha,
                warmup_compact_sha,
            ),
        ] {
            let table = fs::read(path).unwrap();
            assert_eq!(format!("{:x}", Sha256::digest(&table)), raw_sha);
            let compact = fs::read(ledger.join(format!(
                "compact-indexes/{e}/epoch-{e}-{root}-mainnet-slot-to-cid.index"
            )))
            .unwrap();
            assert_eq!(format!("{:x}", Sha256::digest(&compact)), slot_sha);
            let rooted_profile = if e == epoch {
                Some(profile)
            } else if epoch == 258 {
                Some(&EPOCH_257)
            } else {
                None
            };
            let rooted = RootedSlotPresence::configured(e).await.unwrap();
            assert_eq!(rooted.is_some(), rooted_profile.is_some());
            if let Some(r) = &rooted {
                r.verify_compact(&compact).unwrap();
                assert!(r.verify_compact(&compact[..compact.len() - 1]).is_err());
            }
            let legacy = LocalSlotIndex::from_bytes(compact).unwrap();
            assert_eq!(legacy.header.metadata_epoch(), Some(e));
            let mut exceptions = Vec::new();
            for slot in (start..=end).rev() {
                let i = (slot - e * 432000) as usize * 12;
                let o = u64::from_le_bytes(table[i..i + 8].try_into().unwrap());
                let n = u32::from_le_bytes(table[i + 8..i + 12].try_into().unwrap()) as u64;
                let present = n > 0;
                match client.get_range(slot).await {
                    Ok(range) => {
                        assert!(present);
                        assert_eq!(range, (o, n));
                    }
                    Err(SlotOffsetIndexError::SlotNotFound(m, url)) => {
                        assert_eq!(m, slot);
                        assert_eq!((o, n), (0, 0));
                        assert_eq!(url.scheme(), if rooted_profile.is_some() { "file" } else { "http" });
                    }
                    Err(err) => panic!("unexpected range result at {slot}: {err}"),
                }
                let hit = legacy.contains_slot(slot).unwrap();
                if hit != present {
                    exceptions.push(slot);
                }
                if let Some(r) = &rooted {
                    assert_eq!(r.present(slot, hit).unwrap(), present);
                    assert!(r.present(slot, !hit).is_err());
                }
                assert_eq!(
                    map.state(slot),
                    Some(if present {
                        SlotPresenceState::Present
                    } else {
                        SlotPresenceState::Missing
                    })
                );
                assert_eq!(map.next_present_after(slot), next);
                if present {
                    next = Some(slot);
                }
            }
            exceptions.reverse();
            if let Some(p) = rooted_profile {
                let skips: Vec<_> = p.proven_skips.iter().copied()
                    .filter(|slot| (start..=end).contains(slot)).collect();
                assert_eq!(exceptions, skips);
            } else {
                assert!(exceptions.is_empty());
            }
        }
    }
}
