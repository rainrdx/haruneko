﻿import { TestFixture } from '../../../test/WebsitesFixture';

new TestFixture({
    plugin: {
        id: 'mangasect',
        title: 'MangaSect',
    },
    container: {
        url: 'https://mangasect.net/manga/jia-you-shuangsheng-nuyou',
        id: '/manga/jia-you-shuangsheng-nuyou',
        title: 'Jia You Shuangsheng Nuyou',
    },
    child: {
        id: '/manga/jia-you-shuangsheng-nuyou/chapter-297',
        title: 'Chapter 297',
    },
    entry: {
        index: 0,
        size: 116_578,
        type: 'image/jpeg',
    }
}).AssertWebsite();