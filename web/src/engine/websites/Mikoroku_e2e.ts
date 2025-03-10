﻿import { TestFixture } from '../../../test/WebsitesFixture';

const config = {
    plugin: {
        id: 'mikoroku',
        title: 'Mikoroku'
    },
    container: {
        url: 'https://www.mikoroku.com/2024/12/harem-ou-no-isekai-press-manyuuki.html',
        id: '/2024/12/harem-ou-no-isekai-press-manyuuki.html',
        title: 'Harem Ou no Isekai Press Manyuuki'
    },
    child: {
        id: '/2024/07/harem-ou-no-isekai-press-manyuuki_22.html',
        title: 'Chapter 01'
    },
    entry: {
        index: 0,
        size: 215_888,
        type: 'image/webp'
    }
};

new TestFixture(config).AssertWebsite();