#include "max_min_ckks.h"

std::vector<double> coeff_val({0.0, 1.273238551875655,       0.0, -0.42441020299615195,    0.0, 0.25464294463091813,
                               0.0, -0.18188441346502052,    0.0, 0.1414621246790797,      0.0, -0.11573812786240627,
                               0.0, 0.09792859592938771,     0.0, -0.08486774290277588,    0.0, 0.07487956443817181,
                               0.0, -0.06699374222779464,    0.0, 0.060609603030657114,    0.0, -0.055335403426138983,
                               0.0, 0.05090475788583319,     0.0, -0.047130209924583284,   0.0, 0.04387601518901265,
                               0.0, -0.04104146012469417,    0.0, 0.03855024658252758,     0.0, -0.03634351598864421,
                               0.0, 0.03437513594569943,     0.0, -0.032608437110679095,   0.0, 0.031013905132874938,
                               0.0, -0.029567516702177325,   0.0, 0.02824951931783838,     0.0, -0.02704352260561937,
                               0.0, 0.025935812169532054,    0.0, -0.024914824890211098,   0.0, 0.023970743023673285,
                               0.0, -0.02309517686032735,    0.0, 0.02228091419263688,     0.0, -0.021521720738484625,
                               0.0, 0.02081217982554621,     0.0, -0.02014756261194001,    0.0, 0.019523722266175682,
                               0.0, -0.01893700709991235,    0.0, 0.01838418880810082,     0.0, -0.017862402837514252,
                               0.0, 0.017369098557746317,    0.0, -0.016901997404823507,   0.0, 0.01645905754790819,
                               0.0, -0.016038443923073686,   0.0, 0.015638502706528692,    0.0, -0.015257739478449196,
                               0.0, 0.014894800469579828,    0.0, -0.014548456394487201,   0.0, 0.014217588464629198,
                               0.0, -0.013901176245823208,   0.0, 0.013598287082518175,    0.0, -0.013308066857936274,
                               0.0, 0.013029731897283304,    0.0, -0.012762561852409518,   0.0, 0.012505893431831745,
                               0.0, -0.012259114861258818,   0.0, 0.012021660977185657,    0.0, -0.01179300887074859,
                               0.0, 0.011572674011150957,    0.0, -0.011360206788175259,   0.0, 0.011155189421870805,
                               0.0, -0.01095723319470323,    0.0, 0.010765975967577387,    0.0, -0.010581079946370604,
                               0.0, 0.010402229669937174,    0.0, -0.010229130194420174,   0.0, 0.0100615054518764,
                               0.0, -0.009899096763970551,   0.0, 0.009741661493956092,    0.0, -0.009588971822111917,
                               0.0, 0.009440813631691612,    0.0, -0.009296985493879742,   0.0, 0.009157297741669788,
                               0.0, -0.009021571623681564,   0.0, 0.00888963853001945,     0.0, -0.008761339283049648,
                               0.0, 0.008636523486940217,    0.0, -0.008515048930193126,   0.0, 0.008396781036455175,
                               0.0, -0.008281592358758156,   0.0, 0.008169362113677702,    0.0, -0.00805997575129042,
                               0.0, 0.007953324558271782,    0.0, -0.00784930529067446,    0.0, 0.007747819834356052,
                               0.0, -0.007648774890126664,   0.0, 0.007552081682062596,    0.0, -0.007457655686541276,
                               0.0, 0.007365416380710399,    0.0, -0.0072752870084570095,  0.0, 0.007187194362735401,
                               0.0, -0.0071010685827052455,  0.0, 0.00701684296473495,     0.0, -0.00693445378596558,
                               0.0, 0.00685384013968303,     0.0, -0.006774943781375203,   0.0, 0.006697708984867926,
                               0.0, -0.006622082407643203,   0.0, 0.006548012964694983,    0.0, -0.00647545171038316,
                               0.0, 0.006404351727524308,    0.0, -0.00633466802343561,    0.0, 0.006266357432163378,
                               0.0, -0.0061993785227816576,  0.0, 0.006133691512961605,    0.0, -0.0060692581878812445,
                               0.0, 0.0060060418236348835,   0.0, -0.005944007115327876,   0.0, 0.005883120109070612,
                               0.0, -0.005823348138047246,   0.0, 0.005764659761999592,    0.0, -0.005707024710259541,
                               0.0, 0.005650413827772119,    0.0, -0.005594799024235716,   0.0, 0.005540153225824716,
                               0.0, -0.005486450329721153,   0.0, 0.005433665160832674,    0.0, -0.005381773431052311,
                               0.0, 0.005330751700396445,    0.0, -0.00528057734041608,    0.0, 0.005231228499229695,
                               0.0, -0.005182684068631381,   0.0, 0.0051349236525394075,   0.0, -0.005087927537380142,
                               0.0, 0.005041676663585524,    0.0, -0.004996152598858104,   0.0, 0.004951337512394882,
                               0.0, -0.004907214150690918,   0.0, 0.0048637658142136496,   0.0, -0.004820976335464637,
                               0.0, 0.004778830057815365,    0.0, -0.004737311815609309,   0.0, 0.004696406914917171,
                               0.0, -0.004656101115463551,   0.0, 0.0046163806131091474,   0.0, -0.004577232023391056,
                               0.0, 0.004538642365568538,    0.0, -0.004500599047616488,   0.0, 0.004463089851667025,
                               0.0, -0.004426102920283385,   0.0, 0.004389626743207311,    0.0, -0.004353650144770997,
                               0.0, 0.004318162271751679,    0.0, -0.004283152581928701,   0.0, 0.004248610832880011,
                               0.0, -0.004214527071491774,   0.0, 0.004180891623740119,    0.0, -0.00414769508501505,
                               0.0, 0.004114928310772268,    0.0, -0.004082582407580133,   0.0, 0.004050648724582761,
                               0.0, -0.0040191188452525575,  0.0, 0.003987984579512912,    0.0, -0.003957237956147789,
                               0.0, 0.003926871215543282,    0.0, -0.003896876802706868,   0.0, 0.003867247360527829,
                               0.0, -0.0038379757233855403,  0.0, 0.003809054910876625,    0.0, -0.0037804781219428277,
                               0.0, 0.0037522387290591886,   0.0, -0.0037243302728028997,  0.0, 0.003696746456451552,
                               0.0, -0.0036694811410190676,  0.0, 0.003642528340159686,    0.0, -0.0036158822156582044,
                               0.0, 0.0035895370726380512,   0.0, -0.0035634873554007142,  0.0, 0.003537727642997629,
                               0.0, -0.003512252645321855,   0.0, 0.0034870571990428803,   0.0, -0.0034621362639459577,
                               0.0, 0.0034374849191339,      0.0, -0.0034130983596911105,  0.0, 0.0033889718930624067,
                               0.0, -0.00336510093600543,    0.0, 0.0033414810111902856,   0.0, -0.003318107744390611,
                               0.0, 0.0032949768612646783,   0.0, -0.003272084184781894,   0.0, 0.003249425632192008,
                               0.0, -0.0032269972126400203,  0.0, 0.003204795024313184,    0.0, -0.0031828152522588083,
                               0.0, 0.003161054165649607,    0.0, -0.0031395081158081505,  0.0, 0.0031181735336131603,
                               0.0, -0.003097046927672171,   0.0, 0.003076124881856238,    0.0, -0.0030554040536626475,
                               0.0, 0.0030348811718096504,   0.0, -0.003014553034793531,   0.0, 0.002994416508562611,
                               0.0, -0.0029744685252208534,  0.0, 0.002954706080800933,    0.0, -0.0029351262340872246,
                               0.0, 0.002915726104483704,    0.0, -0.0028965028709581294,  0.0, 0.002877453769990715,
                               0.0, -0.0028585760946328777,  0.0, 0.0028398671925144487,   0.0, -0.0028213244650208565,
                               0.0, 0.0028029453654036876,   0.0, -0.0027847273979764034,  0.0, 0.0027666681163556915,
                               0.0, -0.002748765122740043,   0.0, 0.0027310160661865473,   0.0, -0.0027134186419668868,
                               0.0, 0.0026959705899823184,   0.0, -0.002678669694055857,   0.0, 0.002661513780553037,
                               0.0, -0.0026445007176353354,  0.0, 0.002627628413986605,    0.0, -0.002610894818115687,
                               0.0, 0.0025942979171366507,   0.0, -0.0025778357361310495,  0.0, 0.002561506336964629,
                               0.0, -0.00254530781773364,    0.0, 0.0025292383116047703,   0.0, -0.002513295986295378,
                               0.0, 0.002497479042996037,    0.0, -0.002481785715889111,   0.0, 0.0024662142710738582,
                               0.0, -0.0024507630061930533,  0.0, 0.0024354302493184935,   0.0, -0.002420214358699194,
                               0.0, 0.0024051137216255934,   0.0, -0.0023901267542535396,  0.0, 0.0023752519004492235,
                               0.0, -0.002360487631722575,   0.0, 0.0023458324460550674,   0.0, -0.002331284867858009,
                               0.0, 0.00231684344689086,     0.0, -0.002302506758168507,   0.0, 0.0022882734009650307,
                               0.0, -0.002274141998766793,   0.0, 0.0022601111982224796,   0.0, -0.0022461796692044554,
                               0.0, 0.002232346103751967,    0.0, -0.002218609216134907,   0.0, 0.002204967741897062,
                               0.0, -0.0021914204378358252,  0.0, 0.002177966081167718,    0.0, -0.00216460346945673,
                               0.0, 0.0021513314198692507,   0.0, -0.0021381487690540725,  0.0, 0.0021250543724752637,
                               0.0, -0.002112047104275763,   0.0, 0.0020991258566491447,   0.0, -0.0020862895397207107,
                               0.0, 0.0020735370809074967,   0.0, -0.0020608674248863636,  0.0, 0.0020482795328750905,
                               0.0, -0.002035772382708208,   0.0, 0.0020233449680909024,   0.0, -0.0020109962986690497,
                               0.0, 0.001998725399354837,    0.0, -0.001986531310372114,   0.0, 0.0019744130865962397,
                               0.0, -0.001962369797633444,   0.0, 0.001950400527178225,    0.0, -0.0019385043730538603,
                               0.0, 0.0019266804466646775,   0.0, -0.0019149278729768892,  0.0, 0.0019032457900322658,
                               0.0, -0.0018916333489104235,  0.0, 0.0018800897132627483,   0.0, -0.0018686140592885179,
                               0.0, 0.0018572055753056406,   0.0, -0.0018458634616845852,  0.0, 0.0018345869304439693,
                               0.0, -0.0018233752052502607,  0.0, 0.0018122275209478162,   0.0, -0.0018011431236217088,
                               0.0, 0.0017901212700944928,   0.0, -0.0017791612280507636,  0.0, 0.0017682622754719994,
                               0.0, -0.00175742370086011,    0.0, 0.0017466448025935117,   0.0, -0.0017359248892042957,
                               0.0, 0.0017252632787443556,   0.0, -0.001714659299063408,   0.0, 0.0017041122871814544,
                               0.0, -0.001693621589528711,   0.0, 0.0016831865614722994,   0.0, -0.0016728065673106336,
                               0.0, 0.001662480980125372,    0.0, -0.0016522091814888964,  0.0, 0.00164199056149671,
                               0.0, -0.0016318245184385113,  0.0, 0.0016217104588118747,   0.0, -0.0016116477970524827,
                               0.0, 0.0016016359554787394,   0.0, -0.001591674364091116,   0.0, 0.0015817624605076516,
                               0.0, -0.0015718996897383342,  0.0, 0.0015620855042030638,   0.0, -0.0015523193633802048,
                               0.0, 0.001542600733963213,    0.0, -0.0015329290894714345,  0.0, 0.001523303910337303,
                               0.0, -0.0015137246836263926,  0.0, 0.0015041909030980107,   0.0, -0.0014947020688960734,
                               0.0, 0.0014852576876281294,   0.0, -0.0014758572720894084,  0.0, 0.0014665003413278173,
                               0.0, -0.001457186420345492,   0.0, 0.0014479150402296008,   0.0, -0.0014386857377819754,
                               0.0, 0.0014294980557128705,   0.0, -0.0014203515422726673,  0.0, 0.0014112457513864032,
                               0.0, -0.0014021802423733205,  0.0, 0.001393154580020056,    0.0, -0.0013841683343591418,
                               0.0, 0.0013752210806720847,   0.0, -0.0013663123993530204,  0.0, 0.001357441875864185,
                               0.0, -0.0013486091005996171,  0.0, 0.0013398136688888458,   0.0, -0.0013310551808107516,
                               0.0, 0.0013223332412139876,   0.0, -0.0013136474596005053,  0.0, 0.0013049974500181508,
                               0.0, -0.00129638283106064,    0.0, 0.0012878032257222676,   0.0, -0.0012792582613939708,
                               0.0, 0.0012707475697152496,   0.0, -0.001262270786607911,   0.0, 0.0012538275521106596,
                               0.0, -0.0012454175103805518,  0.0, 0.0012370403095757745,   0.0, -0.0012286956018687694,
                               0.0, 0.001220383043283125,    0.0, -0.001212102293735904,   0.0, 0.0012038530168750087,
                               0.0, -0.0011956348801412883,  0.0, 0.00118744755456617,     0.0, -0.001179290714865798,
                               0.0, 0.00117116403923105,     0.0, -0.0011630672094643673,  0.0, 0.0011549999106695646,
                               0.0, -0.0011469618315065818,  0.0, 0.0011389526638065587,   0.0, -0.0011309721028626475,
                               0.0, 0.0011230198470423645,   0.0, -0.0011150955980833448,  0.0, 0.00110719906063524,
                               0.0, -0.0010993299427337893,  0.0, 0.0010914879551441696,   0.0, -0.0010836728119467977,
                               0.0, 0.0010758842298778664,   0.0, -0.0010681219288753362,  0.0, 0.0010603856314559464,
                               0.0, -0.0010526750632730752,  0.0, 0.0010449899524248296,   0.0, -0.0010373300300985564,
                               0.0, 0.0010296950298298716,   0.0, -0.0010220846881758448,  0.0, 0.0010144987439307462,
                               0.0, -0.0010069369388875531,  0.0, 0.000999399016932346,    0.0, -0.0009918847249212267,
                               0.0, 0.0009843938117114833,   0.0, -0.0009769260290463802,  0.0, 0.0009694811306289663,
                               0.0, -0.0009620588729473216,  0.0, 0.0009546590143945243,   0.0, -0.000947281316061995,
                               0.0, 0.0009399255409029253,   0.0, -0.0009325914544790314,  0.0, 0.0009252788241706431,
                               0.0, -0.0009179874198919628,  0.0, 0.0009107170132806663,   0.0, -0.0009034673785136857,
                               0.0, 0.000896238291350905,    0.0, -0.0008890295301006389,  0.0, 0.0008818408745425527,
                               0.0, -0.0008746721069823296,  0.0, 0.0008675230111158489,   0.0, -0.0008603933730902288,
                               0.0, 0.0008532829804449213,   0.0, -0.0008461916230681871,  0.0, 0.0008391190921979665,
                               0.0, -0.0008320651813453611,  0.0, 0.000825029685371135,    0.0, -0.0008180124013109176,
                               0.0, 0.0008110131275066292,   0.0, -0.000804031664436479,   0.0, 0.0007970678138212936,
                               0.0, -0.0007901213794931771,  0.0, 0.0007831921664301451,   0.0, -0.0007762799817246405,
                               0.0, 0.0007693846335510846,   0.0, -0.0007625059321219835,  0.0, 0.0007556436887326282,
                               0.0, -0.0007487977166454553,  0.0, 0.0007419678301482951,   0.0, -0.0007351538454925001,
                               0.0, 0.0007283555798744769,   0.0, -0.0007215728524125843,  0.0, 0.0007148054831584489,
                               0.0, -0.0007080532940222557,  0.0, 0.0007013161077852876,   0.0, -0.0006945937490949542,
                               0.0, 0.000687886043407445,    0.0, -0.0006811928179647344,  0.0, 0.0006745139008588616,
                               0.0, -0.0006678491218683365,  0.0, 0.0006611983116043863,   0.0, -0.0006545613023096713,
                               0.0, 0.000647937927065512,    0.0, -0.0006413280205057086,  0.0, 0.000634731418061645,
                               0.0, -0.0006281479567449442,  0.0, 0.0006215774742521282,   0.0, -0.0006150198098525533,
                               0.0, 0.0006084748035015074,   0.0, -0.0006019422966485215,  0.0, 0.0005954221313993988,
                               0.0, -0.0005889141513675381,  0.0, 0.0005824182007027252,   0.0, -0.0005759341251354782,
                               0.0, 0.0005694617708136505,   0.0, -0.0005630009854910398,  0.0, 0.0005565516172573678,
                               0.0, -0.0005501135158297399,  0.0, 0.0005436865311995816,   0.0, -0.0005372705149631891,
                               0.0, 0.0005308653189597401,   0.0, -0.0005244707966001992,  0.0, 0.0005180868015206974,
                               0.0, -0.0005117131888946272,  0.0, 0.0005053498140881896,   0.0, -0.0004989965339806617,
                               0.0, 0.0004926532056141036,   0.0, -0.00048631968753673954, 0.0, 0.000479995838379317,
                               0.0, -0.00047368151831464256, 0.0, 0.0004673765875317343,   0.0, -0.0004610809077575121,
                               0.0, 0.0004547943406677216,   0.0, -0.000448516749533346,   0.0, 0.0004422479974646434,
                               0.0, -0.0004359879491404226,  0.0, 0.0004297364691749807,   0.0, -0.00042349342355982317,
                               0.0, 0.0004172586782797444,   0.0, -0.00041103210076597047, 0.0, 0.00040481355817075285,
                               0.0, -0.000398602919336607,   0.0, 0.00039240005266473374,  0.0, -0.0003862048281982859,
                               0.0, 0.00038001711562018505,  0.0, -0.00037383678614602773, 0.0, 0.0003676637106388877,
                               0.0, -0.0003614977615074119,  0.0, 0.00035533881069203154,  0.0, -0.0003491867317448418,
                               0.0, 0.0003430413977003729,   0.0, -0.0003369026831876949,  0.0, 0.00033077046226657976,
                               0.0, -0.000324644610599247,   0.0, 0.0003185250032679582,   0.0, -0.0003124115168924586,
                               0.0, 0.000306304027534191,    0.0, -0.00030020241276160187, 0.0, 0.00029410654954749955,
                               0.0, -0.0002880163163656561,  0.0, 0.0002819315910829877,   0.0, -0.0002758522529995749,
                               0.0, 0.00026977818084549036,  0.0, -0.0002637092547790861,  0.0, 0.0002576453542635452,
                               0.0, -0.0002515863602928589,  0.0, 0.0002455321530755362,   0.0, -0.00023948261434132335,
                               0.0, 0.00023343762503804673,  0.0, -0.00022739706759763122, 0.0, 0.00022136082366270521,
                               0.0, -0.00021532877630017045, 0.0, 0.00020930080784300632,  0.0, -0.00020327680197767268,
                               0.0, 0.0001972566416379655,   0.0, -0.00019124021111372065, 0.0, 0.00018522739390759515,
                               0.0, -0.000179218074891294,   0.0, 0.00017321213806612167,  0.0, -0.00016720946886073545,
                               0.0, 0.00016120995177597592,  0.0, -0.00015521347270442033, 0.0, 0.00014921991664376897,
                               0.0, -0.00014322916990898993, 0.0, 0.0001372411179450177,   0.0, -0.00013125564749284527,
                               0.0, 0.0001252726443887036,   0.0, -0.0001192919957433073,  0.0, 0.00011331358775975863,
                               0.0, -0.00010733730789102605, 0.0, 0.00010136304270875312,  0.0, -9.539067990918118e-05,
                               0.0, 8.942010642554739e-05,   0.0, -8.345121017168439e-05,  0.0, 7.748387838570357e-05,
                               0.0, -7.151799921391366e-05,  0.0, 6.555346011130787e-05,   0.0, -5.95901494265071e-05,
                               0.0});

MaxMinCKKS::MaxMinCKKS(std::string ccLocation, std::string pubKeyLocation, std::string multKeyLocation,
                   std::string rotKeyLocation, std::string inputLocation, std::string outputLocation)
    : m_PubKeyLocation(pubKeyLocation), m_MultKeyLocation(multKeyLocation), m_RotKeyLocation(rotKeyLocation),
      m_CCLocation(ccLocation), m_InputLocation(inputLocation), m_OutputLocation(outputLocation)
{
    initCC();
};

void MaxMinCKKS::initCC()
{

    if (!Serial::DeserializeFromFile(m_CCLocation, m_cc, SerType::BINARY))
    {
        std::cerr << "Could not deserialize cryptocontext file" << std::endl;
        std::exit(1);
    }

    if (!Serial::DeserializeFromFile(m_PubKeyLocation, m_PublicKey, SerType::BINARY))
    {
        std::cerr << "Could not deserialize public key file" << std::endl;
        std::exit(1);
    }

    std::ifstream multKeyIStream(m_MultKeyLocation, std::ios::in | std::ios::binary);
    if (!multKeyIStream.is_open())
    {
        std::exit(1);
    }
    if (!m_cc->DeserializeEvalMultKey(multKeyIStream, SerType::BINARY))
    {
        std::cerr << "Could not deserialize rot key file" << std::endl;
        std::exit(1);
    }
    multKeyIStream.close();

    std::ifstream rotKeyIStream(m_RotKeyLocation, std::ios::in | std::ios::binary);
    if (!rotKeyIStream.is_open())
    {
        std::exit(1);
    }

    if (!m_cc->DeserializeEvalAutomorphismKey(rotKeyIStream, SerType::BINARY))
    {
        std::cerr << "Could not deserialize eval rot key file" << std::endl;
        std::exit(1);
    }
    rotKeyIStream.close();

    if (!Serial::DeserializeFromFile(m_InputLocation, m_InputC, SerType::BINARY))
    {
        std::cerr << "Could not deserialize input file" << std::endl;
        std::exit(1);
    }

    array_limit = 8; // 2048
    // array_limit = m_cc->GetEncodingParams()->GetBatchSize();
    Norm_Value = 255.0;
    Norm_Value_Inv = 1.0/Norm_Value;

    std::vector<double> arr_half(array_limit, 0.5);
    std::vector<double> arr_one(array_limit, 1.0);
    std::vector<double> mask_lookup(array_limit, 0); //10...0
    mask_lookup[0]  = Norm_Value; // Included de-normalization and hence changed from 1

    m_Half = m_cc->MakeCKKSPackedPlaintext(arr_half);
    m_One = m_cc->MakeCKKSPackedPlaintext(arr_one);
    m_MaskLookup  = m_cc->MakeCKKSPackedPlaintext(mask_lookup);
}




Ciphertext<DCRTPoly> MaxMinCKKS::cond_swap(const Ciphertext<DCRTPoly>& a, 
                             const Ciphertext<DCRTPoly>& b)
{
    // Compute a + b
    auto sum_cipher = m_cc->EvalAdd(a, b);
    // Compute a - b 
    auto diff_cipher = m_cc->EvalSub(a, b);
    // Choosing a higher degree yields better precision, but a longer runtime.
    uint32_t polyDegree = 500;

    auto abs_diff = m_cc->EvalChebyshevFunction([](double x) -> double { return std::abs(x); }, diff_cipher, -1, 1, polyDegree);

    auto result = m_cc->EvalMult(0.5, m_cc->EvalAdd(sum_cipher, abs_diff));
    return result;
}

void MaxMinCKKS::eval()
{
    // Normalizing
    auto tempPoly = m_cc->EvalMult(m_InputC, Norm_Value_Inv);
    int k_iter = array_limit;

    while (k_iter > 1) {
        k_iter = k_iter >> 1;
        auto rot_cipher = m_cc->EvalRotate(tempPoly, k_iter);
        tempPoly = cond_swap(tempPoly, rot_cipher);
    }
    
    m_OutputC = m_cc->EvalMult(tempPoly, m_MaskLookup); // Result in first position
}


void MaxMinCKKS::deserializeOutput()
{

    if (!Serial::SerializeToFile(m_OutputLocation, m_OutputC, SerType::BINARY))
    {
        std::cerr << " Could not serialize output ciphertext" << std::endl;
    }
}
