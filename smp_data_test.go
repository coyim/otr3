package otr3

import (
	"io"
	"math/big"
)

var randData = []string{
	"ABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCD",
	"BBCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCD",
	"CBCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCD",
	"DBCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCD",
	"EBCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCD",
	"FBCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCD",
	"A1CDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCD",
	"A2CDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCD",
	"A3CDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCD",
	"A4CDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCD",
}

func fixtureRand() io.Reader {
	return fixedRand(randData)
}

var (
	fixtureLong1  = bnFromHex(randData[0][:384])
	fixtureLong2  = bnFromHex(randData[1][:384])
	fixtureLong3  = bnFromHex(randData[2][:384])
	fixtureLong4  = bnFromHex(randData[3][:384])
	fixtureLong5  = bnFromHex(randData[4][:384])
	fixtureLong6  = bnFromHex(randData[5][:384])
	fixtureLong7  = bnFromHex(randData[6][:384])
	fixtureLong8  = bnFromHex(randData[7][:384])
	fixtureShort1 = bnFromHex(randData[0][:32])
	fixtureShort2 = bnFromHex(randData[1][:32])
	fixtureShort3 = bnFromHex(randData[2][:32])
	fixtureShort4 = bnFromHex(randData[3][:32])
	fixtureShort5 = bnFromHex(randData[4][:32])
	fixtureShort6 = bnFromHex(randData[5][:32])
	fixtureShort7 = bnFromHex(randData[6][:32])
	fixtureShort8 = bnFromHex(randData[7][:32])
)

func fixtureSecret() *big.Int {
	return bnFromHex("D9B2E56321F9A9F8E364607C8C82DECD8E8E6209E2CB952C7E649620F5286FE3")
}

func fixtureSmp1() *smp1State {
	var s smp1State
	s.a2 = fixtureShort1
	s.a3 = fixtureShort2
	s.msg = fixtureMessage1()
	return &s
}

func fixtureSmp2() *smp2State {
	var s smp2State
	s.b2 = fixtureShort1
	s.b3 = fixtureShort2
	s.r2 = fixtureShort3
	s.r3 = fixtureShort4
	s.r4 = fixtureShort5
	s.r5 = fixtureShort6
	s.r6 = fixtureShort7
	s.g2 = bnFromHex("8b9e73cca287ed2f46c011090efffcfe394bed51a3ad23e9f7815d9c9c20184ddc0acc2cb0cdd3b8630c453339b6ef7158af705530e33ccac72a855164ca038da837942f3de762ea9af2942c9355dee8eb8b7ce94a3ade33d6a7c79c2a879239c08af22e6987b9345c5e093d33bc8734aaa4019f614dfd65500107756cf6d0ff4591b482d975ca6e43b9f706e969a987306a1a1b905385ffd13d7a24dabc6d513f32a46041cd760e404d1a4c7b6c0b426589ba3ec3d252110578740ccee4bcb3")
	s.g3 = bnFromHex("75cb16d985029162aba03d37b9ef375dca716fc2a4f7d25c6e1b6c511622a47567999230706eda31e44b47c1d7f61df12f49e59142fda0af377d2c5972ad663213db031f131b2abc557e507e6ffbf4dc4a5b44cd0cdf985bc247afb2e5733513f4f022feb5e7a955611175b0ffcfe54763cf7430ce0ede472a7ab5fc0f9f039fcf476be22ec66f8b96759e44a946180f27d16d6c37067e7f1acd3b691b5d56a90b641cc9c8fdac1c41e310e469db4e2f83d28c3dda51b2a36bcbc43d70f0a093")
	s.qb = bnFromHex("69902e8e3f11e631b24343b0788eef58a2cd13afa8f5550749309ace728f2d5a8a4cb9df5916281053d6faaec73c10b66e1cd4cc3c88184e0c524a7ccf693b2a9776227ba27487966695a44053501aab6683fbf4ffe043cab35dae5c077a109b00865b99f7fb9ad7b049dca1dac9f7787d16d35b72f5f4530425def6272b85348f813af1ae64847f01a9bce288e9c47ffcf50cca049f527c4d4593836bd43d22ac71d83b638e0f181e285cc7d54ae0c3e2d7783a4baa03b9fd79950128fada7f")
	s.g3a = bnFromHex("d275468351fd48246e406ee74a8dc3db6ee335067bfa63300ce6a23867a1b2beddbdae9a8a36555fd4837f3ef8bad4f7fd5d7b4f346d7c7b7cb64bd7707eeb515902c66aa0c9323931364471ab93dd315f65c6624c956d74680863a9388cd5d89f1b5033b1cf232b8b6dcffaaea195de4e17cc1ba4c99497be18c011b2ad7742b43fa9ee3f95f7b6da02c8e894d054eb178a7822273655dc286ad15874687fe6671908d83662e7a529744ce4ea8dad49290d19dbe6caba202a825a20a27ee98a")
	s.msg = fixtureMessage2()
	return &s
}

func fixtureSmp3() *smp3State {
	var s smp3State
	s.x = fixtureShort1
	s.r4 = fixtureShort2
	s.r5 = fixtureShort3
	s.r6 = fixtureShort4
	s.qaqb = bnFromHex("8e98e62ca95c07b0a737fb49b810dee8793d8579ff25e5ef5372c12aa725d75f8b098d526c2b506bdd2b1ef1c0fbfb6b28565d212d156959860d04bfab1483f5d4664438cd0964815f34983ad3800fa112877ab3d86c214915b1ef7c6ae6574312a4198b91ef40aa2313da349c9936a306262f5ce3561e5ea8ff51dcc7219242ce875c8baaaa959eb15824ddfb1fa71ad16c988dafe66fa6413b2f6d8a44ec64c2ef5219449052c761dab2f44000169feb42000686a5226273e461b1f539acc9")
	s.papb = bnFromHex("46fdd1e34adb153dcdd734cfcf83db7b9f92aa99e099515acc0e0176ee156d5d4b714fa546de0cdd277313664029b99e5826e9a780e231218f6d3b2e0d6cf45461f34541e23a029f68703e22500e0713c77aeb450c89c760f594309c79b53eb39b87c0c43b6ef542dd65fb935adde4598bf7575e8bec5bdba1636bdc8664feaa9150903ddc819422107171b368d67be6faaafc1bf42946a0b5bd1a7b0511d48affc4f3873c50eca1f75940d5aabcfbd1efc617f7d0d6e1bb360df290d500e4b5")
	s.g3b = bnFromHex("d275468351fd48246e406ee74a8dc3db6ee335067bfa63300ce6a23867a1b2beddbdae9a8a36555fd4837f3ef8bad4f7fd5d7b4f346d7c7b7cb64bd7707eeb515902c66aa0c9323931364471ab93dd315f65c6624c956d74680863a9388cd5d89f1b5033b1cf232b8b6dcffaaea195de4e17cc1ba4c99497be18c011b2ad7742b43fa9ee3f95f7b6da02c8e894d054eb178a7822273655dc286ad15874687fe6671908d83662e7a529744ce4ea8dad49290d19dbe6caba202a825a20a27ee98a")
	s.msg = fixtureMessage3()
	return &s
}

func fixtureMessage1() smp1Message {
	return smp1Message{
		g2a: bnFromHex("8a88c345c63aa25dab9815f8c51f6b7b621a12d31c8220a0579381c1e2e85a2275e2407c79c8e6e1f72ae765804e6b4562ac1b2d634313c70d59752ac119c6da5cb95dde3eedd9c48595b37256f5b64c56fb938eb1131447c9af9054b42841c57d1f41fe5aa510e2bd2965434f46dd0473c60d6114da088c7047760b00bc10287a03afc4c4f30e1c7dd7c9dbd51bdbd049eb2b8921cbdc72b4f69309f61e559c2d6dec9c9ce6f38ccb4dfd07f4cf2cf6e76279b88b297848c473e13f091a0f77"),
		g3a: bnFromHex("d275468351fd48246e406ee74a8dc3db6ee335067bfa63300ce6a23867a1b2beddbdae9a8a36555fd4837f3ef8bad4f7fd5d7b4f346d7c7b7cb64bd7707eeb515902c66aa0c9323931364471ab93dd315f65c6624c956d74680863a9388cd5d89f1b5033b1cf232b8b6dcffaaea195de4e17cc1ba4c99497be18c011b2ad7742b43fa9ee3f95f7b6da02c8e894d054eb178a7822273655dc286ad15874687fe6671908d83662e7a529744ce4ea8dad49290d19dbe6caba202a825a20a27ee98a"),
		c2:  bnFromHex("d3b6ef5528fa97e983395bec165fa4ced7657bdabf3742d60880965c369c880c"),
		d2:  bnFromHex("7fffffffffffffffe487ed5110b4611a62633145c06e0e68948127044533e63a0105df531d89cd9128a5043cc71a026ef7ca8cd9e69d218d98158536f92f8a1ba7f09ab6b6a8e122f242dabb312f3f637a262174d31bf6b585ffae5b7a035bf6f71c35fdad44cfd2d74f9208be258ff324943328f6722d9ee1003e5c50b1df82cc6d241b0e2ae9cd348b1fd47e9267af339d65211b4fcfa466656c89b4217f90102e4aa3ac176a41f6240f32689712b0391c1c659757f4bfb83e6ba66bf8b630"),
		c3:  bnFromHex("57d8cfda442854ecb01b28e631aa9165d51d1192f7f464bf17ea7f6665c05030"),
		d3:  bnFromHex("7fffffffffffffffe487ed5110b4611a62633145c06e0e68948127044533e63a0105df531d89cd9128a5043cc71a026ef7ca8cd9e69d218d98158536f92f8a1ba7f09ab6b6a8e122f242dabb312f3f637a262174d31bf6b585ffae5b7a035bf6f71c35fdad44cfd2d74f9208be258ff324943328f6722d9ee1003e5c50b1df82cc6d241b0e2ae9cd348b1fd47e9267af8140bb2aa65628bcff455920bba95a1392f2fcb5c115f43a7a828b5bf0393c5c775a17a88506a7893ff509d674cd655c"),
	}
}

func fixtureMessage1Q() smp1Message {
	return smp1Message{
		g2a:         bnFromHex("8a88c345c63aa25dab9815f8c51f6b7b621a12d31c8220a0579381c1e2e85a2275e2407c79c8e6e1f72ae765804e6b4562ac1b2d634313c70d59752ac119c6da5cb95dde3eedd9c48595b37256f5b64c56fb938eb1131447c9af9054b42841c57d1f41fe5aa510e2bd2965434f46dd0473c60d6114da088c7047760b00bc10287a03afc4c4f30e1c7dd7c9dbd51bdbd049eb2b8921cbdc72b4f69309f61e559c2d6dec9c9ce6f38ccb4dfd07f4cf2cf6e76279b88b297848c473e13f091a0f77"),
		g3a:         bnFromHex("d275468351fd48246e406ee74a8dc3db6ee335067bfa63300ce6a23867a1b2beddbdae9a8a36555fd4837f3ef8bad4f7fd5d7b4f346d7c7b7cb64bd7707eeb515902c66aa0c9323931364471ab93dd315f65c6624c956d74680863a9388cd5d89f1b5033b1cf232b8b6dcffaaea195de4e17cc1ba4c99497be18c011b2ad7742b43fa9ee3f95f7b6da02c8e894d054eb178a7822273655dc286ad15874687fe6671908d83662e7a529744ce4ea8dad49290d19dbe6caba202a825a20a27ee98a"),
		c2:          bnFromHex("d3b6ef5528fa97e983395bec165fa4ced7657bdabf3742d60880965c369c880c"),
		d2:          bnFromHex("7fffffffffffffffe487ed5110b4611a62633145c06e0e68948127044533e63a0105df531d89cd9128a5043cc71a026ef7ca8cd9e69d218d98158536f92f8a1ba7f09ab6b6a8e122f242dabb312f3f637a262174d31bf6b585ffae5b7a035bf6f71c35fdad44cfd2d74f9208be258ff324943328f6722d9ee1003e5c50b1df82cc6d241b0e2ae9cd348b1fd47e9267af339d65211b4fcfa466656c89b4217f90102e4aa3ac176a41f6240f32689712b0391c1c659757f4bfb83e6ba66bf8b630"),
		c3:          bnFromHex("57d8cfda442854ecb01b28e631aa9165d51d1192f7f464bf17ea7f6665c05030"),
		d3:          bnFromHex("7fffffffffffffffe487ed5110b4611a62633145c06e0e68948127044533e63a0105df531d89cd9128a5043cc71a026ef7ca8cd9e69d218d98158536f92f8a1ba7f09ab6b6a8e122f242dabb312f3f637a262174d31bf6b585ffae5b7a035bf6f71c35fdad44cfd2d74f9208be258ff324943328f6722d9ee1003e5c50b1df82cc6d241b0e2ae9cd348b1fd47e9267af8140bb2aa65628bcff455920bba95a1392f2fcb5c115f43a7a828b5bf0393c5c775a17a88506a7893ff509d674cd655c"),
		hasQuestion: true,
		question:    "What's the clue?",
	}
}

func fixtureMessage1v3() smp1Message {
	return smp1Message{
		g2a: bnFromHex("ff4fb16e465739dff9297312090c2a0271d0579e5871746311b4b4b1cecb4404512f21936268f9903bf7b9ec21f9f68151ece99c892c3adbbccf4511e6d3ddba25f11cf15d140f5db7a2a8b1e4c17d4681ac9466e84c3e518e80c3c1a16c109951e9a4adf2818e7a6ccd6df9d1759065c6a43bb34c0692081619865dec358dba5a2e17cb7f69d998259f26965c794d013b15606e8503968836b284be3929438e46b845b19c0c724e8aee2aff162bbbd95a8195f83f4245f3281ce3a1d7872c92"),
		g3a: bnFromHex("39eaa0273de38f9a16078890a51c37bfce0f113ba445ef54c0f1e72c667a3cbe8d2f4587c3eaad9630027f56543f58f0f0633250287ef6de17c7313e5b8516eace4bddb1d9cdfa7729a48db9255e073f6f82ab37684843a839d785d330295322d75208093566fbec4bd01e8f462ee71e393af34de8688a5244b8aaf5fae2019308b3abd790c5b1eb971bf4505d376af071413389d56332cfe5b98fb30b77f72ddf2a629275b68c364de8f76137aa953ce9b3746d2c919a9827459f08ead78c71"),
	}
}

func fixtureMessage2() smp2Message {
	return smp2Message{
		g2b: bnFromHex("8a88c345c63aa25dab9815f8c51f6b7b621a12d31c8220a0579381c1e2e85a2275e2407c79c8e6e1f72ae765804e6b4562ac1b2d634313c70d59752ac119c6da5cb95dde3eedd9c48595b37256f5b64c56fb938eb1131447c9af9054b42841c57d1f41fe5aa510e2bd2965434f46dd0473c60d6114da088c7047760b00bc10287a03afc4c4f30e1c7dd7c9dbd51bdbd049eb2b8921cbdc72b4f69309f61e559c2d6dec9c9ce6f38ccb4dfd07f4cf2cf6e76279b88b297848c473e13f091a0f77"),
		g3b: bnFromHex("d275468351fd48246e406ee74a8dc3db6ee335067bfa63300ce6a23867a1b2beddbdae9a8a36555fd4837f3ef8bad4f7fd5d7b4f346d7c7b7cb64bd7707eeb515902c66aa0c9323931364471ab93dd315f65c6624c956d74680863a9388cd5d89f1b5033b1cf232b8b6dcffaaea195de4e17cc1ba4c99497be18c011b2ad7742b43fa9ee3f95f7b6da02c8e894d054eb178a7822273655dc286ad15874687fe6671908d83662e7a529744ce4ea8dad49290d19dbe6caba202a825a20a27ee98a"),
		c2:  bnFromHex("5f78f76ed595e10b8ec22a10b848a2dbfc01d5b4bf4f3354fa7d9e7a7b89be3c"),
		d2:  bnFromHex("7fffffffffffffffe487ed5110b4611a62633145c06e0e68948127044533e63a0105df531d89cd9128a5043cc71a026ef7ca8cd9e69d218d98158536f92f8a1ba7f09ab6b6a8e122f242dabb312f3f637a262174d31bf6b585ffae5b7a035bf6f71c35fdad44cfd2d74f9208be258ff324943328f6722d9ee1003e5c50b1df82cc6d241b0e2ae9cd348b1fd47e9267af81a02d5a40ae02cf4b98b37d6f98f1c0fc61fb686e150da2863071729e0bec44d63b7abd8751f58a1a5499c8526241c0"),
		c3:  bnFromHex("e6417f7a922aa04d488ccd60062eaa374b772054c4e7bf72e6a570db604c3bcc"),
		d3:  bnFromHex("7fffffffffffffffe487ed5110b4611a62633145c06e0e68948127044533e63a0105df531d89cd9128a5043cc71a026ef7ca8cd9e69d218d98158536f92f8a1ba7f09ab6b6a8e122f242dabb312f3f637a262174d31bf6b585ffae5b7a035bf6f71c35fdad44cfd2d74f9208be258ff324943328f6722d9ee1003e5c50b1df82cc6d241b0e2ae9cd348b1fd47e9267af18c7d9799344f5a6052f526c1b70ab3aa4098d714850b6535a758a04e6cc15cd396287aa3a2009185e9793757c748570"),
		d5:  bnFromHex("7fffffffffffffffe487ed5110b4611a62633145c06e0e68948127044533e63a0105df531d89cd9128a5043cc71a026ef7ca8cd9e69d218d98158536f92f8a1ba7f09ab6b6a8e122f242dabb312f3f637a262174d31bf6b585ffae5b7a035bf6f71c35fdad44cfd2d74f9208be258ff324943328f6722d9ee1003e5c50b1df82cc6d241b0e2ae9cd348b1fd47e9267afa7eabf42bf076f4040403db48ffb54afd86d74189952bdf7d7c76b428a31c54a1ce43d9f900d73c4c74e8f9caa8efb8e"),
		d6:  bnFromHex("7fffffffffffffffe487ed5110b4611a62633145c06e0e68948127044533e63a0105df531d89cd9128a5043cc71a026ef7ca8cd9e69d218d98158536f92f8a1ba7f09ab6b6a8e122f242dabb312f3f637a262174d31bf6b585ffae5b7a035bf6f71c35fdad44cfd2d74f9208be258ff324943328f6722d9ee1003e5c50b1df82b49ff02bddc494c3a81caeefaaaebfda10656000c64956f65dc53b5ef82e8641a877db4a709931afc80f7e4521723d1a0b646aaaddc46ac095d3d47b052234ea"),
		pb:  bnFromHex("70f18724fd6263a694b82a6272e938a81f56b7373c29a4f78ee2d5dd94bf7fe8ff59d837ca2686088f62f7ec178a5b47bcdec3b6f2af7820d6583d5358a714a5cf6d943371289cce76a9cc09e04306bcffde5a6dbeb887a5e18aff1740be083e2b4a505e30fa56771d5be27984ca85e90a9d90faa278db0b5d51f334e80cfab14cb5e7fed9c6d3d0eaff5c1f3dbe698ba8f0db3517e892474cc899d46866546ea306d4f6e0a11546305c4fd50ad8e49163fb9abc3294612868d310d2e5755d4d"),
		qb:  bnFromHex("69902e8e3f11e631b24343b0788eef58a2cd13afa8f5550749309ace728f2d5a8a4cb9df5916281053d6faaec73c10b66e1cd4cc3c88184e0c524a7ccf693b2a9776227ba27487966695a44053501aab6683fbf4ffe043cab35dae5c077a109b00865b99f7fb9ad7b049dca1dac9f7787d16d35b72f5f4530425def6272b85348f813af1ae64847f01a9bce288e9c47ffcf50cca049f527c4d4593836bd43d22ac71d83b638e0f181e285cc7d54ae0c3e2d7783a4baa03b9fd79950128fada7f"),
		cp:  bnFromHex("1bfd38604f788c140186388f48adb32c49725b1fb0a7d152fb02a96dede93f36"),
	}
}

func fixtureMessage3() smp3Message {
	s := smp3Message{
		pa: bnFromHex("8EE76C232535FA68E18C13817056B7415E8FE8224AD15FA317C8D6F1AF17A0E45F538930F10DB29943E54E8D39D145E51B53D6A58C9E499A6353BBF378FD9D32370105EA4DEF5C88B755EFA485EF70C9097DEEA76A853F32CE98AA7ECE96073C0ABEDC91D1C9C0E092E86D36F4F1319EC7E8E40D4156F04CF18D7A79B01D44EBBB685F272FA39AA8C90662E4D8FBFB3F0A9F06478366C6708741F26FFA5F492CDD07D1F73A93BC18B3ECBE9F4071EC9FE600BCB67A8BC76920ED2C61BB94D07C"),
		qa: bnFromHex("5533DDDE3704615657E1A654293D110C1557E6913DD8B79A5F15B5AF1F276153DBB8DEC7E17D157CF20DD54BC9B9373D6D0F2B44B3E88AD6F926B0D18DD87940C6E969184F1B184E441D379234C52EBB67584863925D775A423A962DC88A1A2E58152C1E7458BDF6FE762C5EA580A46C9AF6AD34D47F26B12D514F637FFD1D15D1CFB3FF330B53F1213D759A8F528ED4C22A9003A186A65F509EC96DB02420EF24D43E08FF469A0B4558B3A39778668E463647858C241B81F61A6C97FD076D72"),
		cp: bnFromHex("F1F0147F5E53C85F410DB88C0C04370E45C341B735DA7CAF363B2497A358FCE7"),
		d5: bnFromHex("7FFFFFFFFFFFFFFFE487ED5110B4611A62633145C06E0E68948127044533E63A0105DF531D89CD9128A5043CC71A026EF7CA8CD9E69D218D98158536F92F8A1BA7F09AB6B6A8E122F242DABB312F3F637A262174D31BF6B585FFAE5B7A035BF6F71C35FDAD44CFD2D74F9208BE258FF324943328F6722D9EE1003E5C50B1DF82CC6D241B0E2AE9CD348B1FD47E9267AF1F54F142B3021B8C3E37676EA9D9D2CEFC3191FB331434AFD0328AC85221A9BC5F4D56D88694EC56144A03179AA1D9D1"),
		d6: bnFromHex("7FFFFFFFFFFFFFFFE487ED5110B4611A62633145C06E0E68948127044533E63A0105DF531D89CD9128A5043CC71A026EF7CA8CD9E69D218D98158536F92F8A1BA7F09AB6B6A8E122F242DABB312F3F637A262174D31BF6B585FFAE5B7A035BF6F71C35FDAD44CFD2D74F9208BE258FF324943328F6722D9EE1003E5C50B1DF81FEAF9103645C8C45A77954B47CFAFDA9F63D78BB41138DD8D85DA319B2F61CDE6DE2F21A5B4FAF4BFE57D3FBC5289E2B983E28ABB5A9D7A30DEDD2B3A72541F7"),
		d7: bnFromHex("7fffffffffffffffe487ed5110b4611a62633145c06e0e68948127044533e63a0105df531d89cd9128a5043cc71a026ef7ca8cd9e69d218d98158536f92f8a1ba7f09ab6b6a8e122f242dabb312f3f637a262174d31bf6b585ffae5b7a035bf6f71c35fdad44cfd2d74f9208be258ff324943328f6722d9ee1003e5c50b1df82cc6d241b0e2ae9cd348b1fd47e9267af800080da56542af5a4ac8a711e16d8a7c7e43f631013427303aa7329b9e6c09bcc217f11d687257f7bd4389b9d9dc788"),
		ra: bnFromHex("6ca88ee8cf412f4ed088d67c2e22f28569c83833669abf0393688929b4a4e85cbdbcdbd3e30a5291edf31f108e10f296413d686a3567a7859e889dad8cf4089e9f6dd1299aba36fa09742e404f80eaadbcecb0ac38c861f0c15a606bcc33987c3611cf72ebccf5fbe055b28f14ff6ea78fc793287b44f4e832e97234ef1f26147d4bf9ad510bf6f8a3319cafaf7bad6af55d9d3f3e0bdc3877538e2b5c0b01d0eb1b5e4945f469ed9fccfb8ed5f588e7e4badaed7f9f4a3a205a594adcf3eb1e"),
		cr: bnFromHex("598d52c0ffdb62c6fc98e4b3ebafc06313fb5a60fc9e3887eca20d7d251e9954"),
	}

	return s
}

func fixtureMessage4() smp4Message {
	s := smp4Message{
		rb: bnFromHex("6ca88ee8cf412f4ed088d67c2e22f28569c83833669abf0393688929b4a4e85cbdbcdbd3e30a5291edf31f108e10f296413d686a3567a7859e889dad8cf4089e9f6dd1299aba36fa09742e404f80eaadbcecb0ac38c861f0c15a606bcc33987c3611cf72ebccf5fbe055b28f14ff6ea78fc793287b44f4e832e97234ef1f26147d4bf9ad510bf6f8a3319cafaf7bad6af55d9d3f3e0bdc3877538e2b5c0b01d0eb1b5e4945f469ed9fccfb8ed5f588e7e4badaed7f9f4a3a205a594adcf3eb1e"),
		cr: bnFromHex("91c6b49e6cd0db5af988fd95ab2e65959607f693305440f2a3e32d6304f02714"),
		d7: bnFromHex("7fffffffffffffffe487ed5110b4611a62633145c06e0e68948127044533e63a0105df531d89cd9128a5043cc71a026ef7ca8cd9e69d218d98158536f92f8a1ba7f09ab6b6a8e122f242dabb312f3f637a262174d31bf6b585ffae5b7a035bf6f71c35fdad44cfd2d74f9208be258ff324943328f6722d9ee1003e5c50b1df82cc6d241b0e2ae9cd348b1fd47e9267af56c16aaeb95ed529fe253547f6d3f246c32062e08372b03f89223f84da5de2791a6b8dca81fdd15a2d8c29c8a66004c8"),
	}

	return s
}

func fixtureMessageAbort() smpMessageAbort {
	return smpMessageAbort{}
}
