import { TestFixture } from '../../../test/WebsitesFixture';

new TestFixture({
    plugin: {
        id: 'rizzcomics',
        title: 'Rizz Comics'
    },
    container: {
        url: 'https://rizzfables.com/series/r2311170-demonic-master-of-mount-kunlun',
        id: '/series/r2311170-demonic-master-of-mount-kunlun',
        title: 'Demonic Master of Mount Kunlun'
    },
    child: {
        id: '/chapter/r2311170-demonic-master-of-mount-kunlun-chapter-49',
        title: 'Chapter 49'
    },
    entry: {
        index: 0,
        size: 155_262,
        type: 'image/webp'
    }
}).AssertWebsite();