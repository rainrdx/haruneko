﻿import { TestFixture } from '../../../test/WebsitesFixture';

const config = {
    plugin: {
        id: 'gufengmh8',
        title: '古风漫画网 (GuFengMH8)'
    },
    container: {
        url: 'https://www.gufengmh.com/manhua/moshifanren/',
        id: '/manhua/moshifanren/',
        title: '末世凡人'
    },
    child: {
        id: '/manhua/moshifanren/252431.html',
        title: '第01话'
    },
    entry: {
        index: 1,
        size: 279_731,
        type: 'image/jpeg'
    }
};

new TestFixture(config).AssertWebsite();